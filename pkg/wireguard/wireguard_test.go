package wireguard

import (
	"context"
	"errors"
	"io/fs"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type memoryKeystore struct {
	mu      sync.Mutex
	secrets map[string][]byte
}

type failedProbeRunner struct {
	Runner
	err error
}

func (r failedProbeRunner) Run(context.Context, string, ...string) (string, error) { return "", r.err }

func TestLinuxDownDoesNotTreatProbeFailureAsAbsent(t *testing.T) {
	for _, cause := range []error{errors.New("permission denied"), context.Canceled, errors.New("executable file not found")} {
		manager := NewLinuxManagerWithRunner(nil, "nkg0", failedProbeRunner{err: cause})
		if err := manager.Down(context.Background()); !errors.Is(err, cause) {
			t.Fatalf("probe failure suppressed: %v", err)
		}
	}
}

func (k *memoryKeystore) ReadSecret(name string) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	value, ok := k.secrets[name]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return value, nil
}
func (k *memoryKeystore) WriteSecret(name string, data []byte) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.secrets[name] = append([]byte(nil), data...)
	return nil
}
func (k *memoryKeystore) Has(name string) bool { _, err := k.ReadSecret(name); return err == nil }

type recordingRunner struct {
	mu       sync.Mutex
	calls    []string
	stdin    []string
	existing bool
}

func (r *recordingRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	line := name + " " + strings.Join(args, " ")
	r.calls = append(r.calls, line)
	switch {
	case line == "wg genkey":
		return "cHJpdmF0ZWtleXByaXZhdGVrZXlwcml2YXRla2V5MTI=\n", nil
	case strings.HasPrefix(line, "ip link show"):
		if !r.existing {
			return "", errors.New("does not exist")
		}
	case strings.HasPrefix(line, "ip link add"):
		r.existing = true
	case strings.HasSuffix(line, " dump"):
		now := time.Now().Unix()
		return "priv\tPUBSELF=\t51820\toff\n" +
			"PEERA=\t(none)\t203.0.113.5:51820\t10.88.0.3/32\t" + itoa(now-10) + "\t100\t200\t25\n" +
			"PEERB=\t(none)\t(none)\t10.88.0.7/32\t0\t0\t0\toff\n", nil
	}
	return "", nil
}
func (r *recordingRunner) RunStdin(_ context.Context, input string, name string, args ...string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, name+" "+strings.Join(args, " "))
	r.stdin = append(r.stdin, input)
	if name == "wg" && len(args) > 0 && args[0] == "pubkey" {
		return "PUBSELF=\n", nil
	}
	return "", nil
}
func (r *recordingRunner) Look(string) (string, error) { return "/usr/bin/x", nil }

func itoa(v int64) string { return strconv.FormatInt(v, 10) }

func TestRenderConfNeverWritesToAFile(t *testing.T) {
	conf, err := renderConf("PRIV=", InterfaceConfig{ListenPort: 51820, Peers: []PeerConfig{{
		DeviceID: "nkg_a", PublicKey: "PEERA=", AllowedIPs: []string{"10.88.0.3/32"}, Endpoint: "203.0.113.5:51820", PersistentKeepalive: 25,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"PrivateKey = PRIV=", "ListenPort = 51820", "PublicKey = PEERA=", "AllowedIPs = 10.88.0.3/32", "Endpoint = 203.0.113.5:51820", "PersistentKeepalive = 25"} {
		if !strings.Contains(conf, want) {
			t.Fatalf("missing %q in\n%s", want, conf)
		}
	}
	if _, err := renderConf("PRIV=", InterfaceConfig{Peers: []PeerConfig{{DeviceID: "x"}}}); err == nil {
		t.Fatal("peer without a key rendered")
	}
}

func TestEnsureInterfacePassesKeyOnStdinOnly(t *testing.T) {
	runner := &recordingRunner{}
	store := &memoryKeystore{secrets: map[string][]byte{}}
	manager := NewLinuxManagerWithRunner(store, "nkg0", runner)
	err := manager.EnsureInterface(context.Background(), InterfaceConfig{Name: "nkg0", Address: "10.88.0.2/16", ListenPort: 51820})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(runner.calls, "\n")
	for _, want := range []string{"wg genkey", "ip link add dev nkg0 type wireguard", "wg setconf nkg0 /dev/stdin", "ip address add 10.88.0.2/16 dev nkg0", "ip link set up dev nkg0"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %q in calls:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "cHJpdmF0ZWtleX") {
		t.Fatal("private key appeared in a command line, where `ps` can read it")
	}
	if !store.Has(PrivateKeyName) {
		t.Fatal("private key was not persisted")
	}
}

func TestUpdateEndpointIsSingleSetCommand(t *testing.T) {
	runner := &recordingRunner{}
	manager := NewLinuxManagerWithRunner(&memoryKeystore{secrets: map[string][]byte{}}, "nkg0", runner)
	if err := manager.UpdateEndpoint(context.Background(), "PEERA=", "198.51.100.9:4000"); err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 1 || runner.calls[0] != "wg set nkg0 peer PEERA= endpoint 198.51.100.9:4000" {
		t.Fatalf("roaming must be one in-place update, got %v", runner.calls)
	}
}

func TestParseDump(t *testing.T) {
	runner := &recordingRunner{}
	out, _ := runner.Run(context.Background(), "wg", "show", "nkg0", "dump")
	status := parseDump(out, time.Now())
	if status.PublicKey != "PUBSELF=" || status.ListenPort != 51820 || len(status.Peers) != 2 {
		t.Fatalf("bad parse: %+v", status)
	}
	if !status.Peers[0].Current || status.Peers[0].TransferRxBytes != 100 {
		t.Fatalf("peer A should be current: %+v", status.Peers[0])
	}
	if status.Peers[1].Current || status.Peers[1].Endpoint != "" {
		t.Fatalf("peer B has never handshaken: %+v", status.Peers[1])
	}
}

func TestRestartKeepsLivePeers(t *testing.T) {
	runner := &recordingRunner{existing: true}
	store := &memoryKeystore{secrets: map[string][]byte{PrivateKeyName: []byte("KEY=\n")}}
	manager := NewLinuxManagerWithRunner(store, "nkg0", runner)
	if err := manager.EnsureInterface(context.Background(), InterfaceConfig{Name: "nkg0", ListenPort: 51820}); err != nil {
		t.Fatal(err)
	}
	for _, call := range runner.calls {
		if strings.Contains(call, "setconf") || strings.Contains(call, "link add") {
			t.Fatalf("restart on an existing interface ran %q, which would drop live tunnels", call)
		}
	}
	if !strings.Contains(strings.Join(runner.calls, "\n"), "wg set nkg0 private-key /dev/stdin listen-port 51820") {
		t.Fatalf("key/port not reasserted: %v", runner.calls)
	}
}
