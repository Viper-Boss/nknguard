package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Viper-Boss/nknguard/internal/config"
	"github.com/Viper-Boss/nknguard/internal/state"
	"github.com/Viper-Boss/nknguard/pkg/identity"
	"github.com/Viper-Boss/nknguard/pkg/membership"
	"github.com/Viper-Boss/nknguard/pkg/mesh"
	"github.com/Viper-Boss/nknguard/pkg/protocol"
	"github.com/Viper-Boss/nknguard/pkg/signaling"
	"github.com/Viper-Boss/nknguard/pkg/wireguard"
)

type lifecycleWG struct {
	wireguard.Manager
	mu                 sync.Mutex
	up                 bool
	removeErr, downErr error
	removed            []string
}

func (*lifecycleWG) Supported(context.Context) (wireguard.State, string) {
	return wireguard.StateDown, ""
}
func (w *lifecycleWG) EnsureInterface(context.Context, wireguard.InterfaceConfig) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.up = true
	return nil
}
func (w *lifecycleWG) Status(context.Context) wireguard.Status {
	w.mu.Lock()
	defer w.mu.Unlock()
	s := wireguard.StateDown
	if w.up {
		s = wireguard.StateUp
	}
	return wireguard.Status{State: s}
}
func (*lifecycleWG) Stats(context.Context) ([]wireguard.PeerStats, error) { return nil, nil }

// The controller now publishes before NKN is ready, including in the offline
// dashboard lifecycle test. Its fake must implement the key lookup explicitly.
func (*lifecycleWG) PublicKey(context.Context) (string, error) {
	return "", errors.New("test tunnel has no public key")
}
func (w *lifecycleWG) RemovePeer(_ context.Context, key string) error {
	w.removed = append(w.removed, key)
	return w.removeErr
}
func (w *lifecycleWG) Down(context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.downErr != nil {
		return w.downErr
	}
	w.up = false
	return nil
}

func ownerForLifecycle(t *testing.T) (*Node, *mesh.Controller, config.Config) {
	t.Helper()
	cfg := config.Default()
	cfg.Paths.StateDir = t.TempDir()
	cfg.Paths.Socket = filepath.Join(cfg.Paths.StateDir, "run", "api.sock")
	node, err := OpenNode(cfg)
	if err != nil {
		t.Fatal(err)
	}
	id, _, err := node.CreateNetwork()
	if err != nil {
		t.Fatal(err)
	}
	c := mesh.New()
	c.Config.NetworkID = id
	c.Config.RequireApproval = true
	return node, c, cfg
}

func TestConcurrentRevocationsPersistEveryRemoval(t *testing.T) {
	node, c, _ := ownerForLifecycle(t)
	current, _ := node.State.LoadMembership()
	for i := 0; i < 24; i++ {
		id := fmt.Sprintf("device-%d", i)
		current.Members = append(current.Members, id)
		c.ApproveDevice(id)
	}
	if err := node.State.SaveMembership(current); err != nil {
		t.Fatal(err)
	}
	p := NewPairing(node, c, nil)
	start := make(chan struct{})
	errs := make(chan error, len(current.Members))
	for _, id := range current.Members {
		go func(id string) { <-start; errs <- p.Revoke(context.Background(), id) }(id)
	}
	close(start)
	for range current.Members {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	stored, err := node.State.LoadMembership()
	if err != nil || len(stored.Members) != 0 {
		t.Fatalf("revocation lost on disk: %v %v", stored.Members, err)
	}
}

type blockedApprovalTransport struct {
	signaling.Transport
	entered, release chan struct{}
}

func (*blockedApprovalTransport) LocalAddress() string { return "nas" }
func (s *blockedApprovalTransport) SendAddress(context.Context, string, protocol.Envelope) error {
	close(s.entered)
	<-s.release
	return errors.New("delivery failed")
}

func TestApprovalRollbackDoesNotRestoreConcurrentRevocation(t *testing.T) {
	node, c, _ := ownerForLifecycle(t)
	old, _ := identity.Generate()
	fresh, _ := identity.Generate()
	current, _ := node.State.LoadMembership()
	current.Members = []string{old.DeviceID()}
	c.ApproveDevice(old.DeviceID())
	if err := node.State.SaveMembership(current); err != nil {
		t.Fatal(err)
	}
	wire := &blockedApprovalTransport{entered: make(chan struct{}), release: make(chan struct{})}
	p := NewPairing(node, c, wire)
	p.pending[fresh.DeviceID()] = pendingRequest{PendingPair: PendingPair{DeviceID: fresh.DeviceID(), ExpiresAt: time.Now().Add(time.Minute)}, request: protocol.PairRequest{NKNAddress: "client", Token: "token"}}
	approved := make(chan error, 1)
	revoked := make(chan error, 1)
	go func() { approved <- p.Approve(context.Background(), fresh.DeviceID()) }()
	<-wire.entered
	go func() { revoked <- p.Revoke(context.Background(), old.DeviceID()) }()
	select {
	case err := <-revoked:
		close(wire.release)
		t.Fatalf("revoke raced approval transaction: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(wire.release)
	if err := <-approved; err == nil {
		t.Fatal("delivery failure accepted")
	}
	if err := <-revoked; err != nil {
		t.Fatal(err)
	}
	stored, _ := node.State.LoadMembership()
	if len(stored.Members) != 0 {
		t.Fatalf("rollback restored revoked member: %v", stored.Members)
	}
}

func TestFailedRevocationSurvivesRestartAndRetries(t *testing.T) {
	node, c, cfg := ownerForLifecycle(t)
	current, _ := node.State.LoadMembership()
	current.Members = []string{"device"}
	current.PendingRemovals = []string{"public"}
	if err := node.State.SaveMembership(current); err != nil {
		t.Fatal(err)
	}
	w := &lifecycleWG{removeErr: errors.New("remove denied")}
	c.WireGuard = w
	c.ApproveDevice("device")
	p := NewPairing(node, c, nil)
	if err := p.Revoke(context.Background(), "device"); err == nil {
		t.Fatal("revocation claimed data-plane cleanup succeeded")
	}
	reopened, err := OpenNode(cfg)
	if err != nil {
		t.Fatal(err)
	}
	stored, _ := reopened.State.LoadMembership()
	if len(stored.Members) != 0 || len(stored.PendingRemovals) != 1 {
		t.Fatalf("revocation not durable: %+v", stored)
	}
	w.removeErr = nil
	retry := mesh.New()
	retry.WireGuard = w
	if err := NewPairing(reopened, retry, nil).CleanPending(context.Background()); err != nil {
		t.Fatal(err)
	}
	stored, _ = reopened.State.LoadMembership()
	if len(stored.PendingRemovals) != 0 || len(w.removed) != 2 {
		t.Fatalf("pending key not retried: %+v %v", stored, w.removed)
	}
}

func TestShutdownResultDistinguishesCleanupFailureAndCrash(t *testing.T) {
	store := state.New(t.TempDir())
	if err := store.SaveShutdown(state.Shutdown{}); err != nil {
		t.Fatal(err)
	}
	if CheckShutdown(store.Dir()) == nil {
		t.Fatal("incomplete cleanup accepted")
	}
	w := &lifecycleWG{downErr: errors.New("uninstall failed")}
	if cleanupTunnel(w, store) == nil || CheckShutdown(store.Dir()) == nil {
		t.Fatal("cleanup failure accepted")
	}
	w.downErr = nil
	if err := cleanupTunnel(w, store); err != nil {
		t.Fatal(err)
	}
	if err := CheckShutdown(store.Dir()); err != nil {
		t.Fatal(err)
	}
}

func TestInstanceLockRejectsDuplicateAndReleases(t *testing.T) {
	path := filepath.Join(t.TempDir(), "daemon.lock")
	first, err := acquireInstanceLock(path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if second, err := acquireInstanceLock(path); err == nil {
		second.Close()
		t.Fatal("duplicate acquired active lock")
	}
	first.Close()
	next, err := acquireInstanceLock(path)
	if err != nil {
		t.Fatal(err)
	}
	next.Close()
}

func TestDashboardAvailableWhileNKNFactoryBlocked(t *testing.T) {
	node, _, cfg := ownerForLifecycle(t)
	// Unix sockets have a short path limit, including on Windows.
	socketDir, err := os.MkdirTemp("", "nkg-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(socketDir)
	cfg.Paths.Socket = filepath.Join(socketDir, "api.sock")
	password := "offline-panel-test-password"
	if err := node.SetDashboardPassword(password); err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Dashboard.Listen = l.Addr().String()
	l.Close()
	original := controlPlaneFactory
	defer func() { controlPlaneFactory = original }()
	entered := make(chan struct{})
	controlPlaneFactory = func(ctx context.Context, _ config.Config, _ *identity.Keystore, _ *membership.Key, _ *slog.Logger) (*ControlPlane, error) {
		close(entered)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w := &lifecycleWG{}
	done := make(chan error, 1)
	go func() {
		defer close(done)
		done <- runDaemon(ctx, cfg, io.Discard, func(wireguard.Keystore, string, string) wireguard.Manager { return w })
	}()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("daemon did not stop")
		}
	}()
	select {
	case <-entered:
	case err := <-done:
		t.Fatalf("startup failed: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("NKN factory not reached")
	}
	request, _ := http.NewRequest("GET", "http://"+cfg.Dashboard.Listen+"/api/status", nil)
	client := &http.Client{Timeout: 2 * time.Second}
	login, _ := http.NewRequest("POST", "http://"+cfg.Dashboard.Listen+"/api/auth/login", strings.NewReader(`{"username":"admin","password":"`+password+`"}`))
	login.Header.Set("X-NKNGuard-UI", "1")
	loggedIn, err := client.Do(login)
	if err != nil {
		t.Fatal(err)
	}
	loggedIn.Body.Close()
	if loggedIn.StatusCode != http.StatusOK || len(loggedIn.Cookies()) != 1 {
		t.Fatalf("login failed: %d", loggedIn.StatusCode)
	}
	request.AddCookie(loggedIn.Cookies()[0])
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("offline dashboard status: %d", response.StatusCode)
	}
	invite, _ := http.NewRequest("POST", "http://"+cfg.Dashboard.Listen+"/api/pair/invite", nil)
	invite.AddCookie(loggedIn.Cookies()[0])
	invite.Header.Set("X-NKNGuard-UI", "1")
	response, err = client.Do(invite)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("offline pairing status: %d", response.StatusCode)
	}
	if duplicate, err := acquireInstanceLock(filepath.Join(cfg.Paths.StateDir, "daemon.lock")); err == nil {
		duplicate.Close()
		t.Error("running daemon has no state lock")
	}
}
