//go:build windows

package wireguard

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Viper-Boss/nknguard/pkg/identity"
)

type windowsRunner struct {
	installed bool
	secured   bool
	confPath  string
}

func (r *windowsRunner) Look(name string) (string, error) { return name, nil }
func (r *windowsRunner) RunStdin(context.Context, string, string, ...string) (string, error) {
	return "", errors.New("unexpected stdin command")
}
func (r *windowsRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	switch {
	case name == "sc.exe" && len(args) == 4 && args[0] == "config":
		return "", nil
	case name == "icacls":
		r.secured = true
		return "", nil
	case name == "wireguard" && len(args) == 2 && args[0] == "/installtunnelservice":
		if !r.secured {
			return "", errors.New("configuration written before ACL")
		}
		r.confPath = args[1]
		r.installed = true
		return "", nil
	case name == "wireguard" && len(args) == 2 && args[0] == "/uninstalltunnelservice":
		r.installed = false
		return "", nil
	case name == "wg" && len(args) == 3 && args[0] == "show" && args[2] == "dump":
		if !r.installed {
			return "", errors.New("not running")
		}
		return "private\tpublic\t51820\toff\n", nil
	case name == "wg" && len(args) >= 2 && args[0] == "set":
		return "", nil
	}
	return "", errors.New("unexpected command")
}

func TestWindowsManagerTunnelLifecycle(t *testing.T) {
	dir := t.TempDir()
	store := identity.NewKeystore(filepath.Join(dir, "keys"))
	runner := &windowsRunner{}
	manager := &WindowsManager{store: store, runner: runner, name: "nknguard", dir: filepath.Join(dir, "tunnels")}
	ctx := context.Background()
	if !validTunnelName("nknguard") || validTunnelName("../other") {
		t.Fatal("tunnel name validation failed")
	}
	if err := manager.EnsureInterface(ctx, InterfaceConfig{Name: "nknguard", Address: "10.88.12.2/16"}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(runner.confPath)
	if err != nil || !strings.Contains(string(raw), "Address = 10.88.12.2/16") ||
		!strings.Contains(string(raw), "PrivateKey = ") {
		t.Fatalf("tunnel configuration: %v", err)
	}
	if err := manager.AddPeer(ctx, PeerConfig{PublicKey: "peer", AllowedIPs: []string{"10.88.12.1/32"}}); err != nil {
		t.Fatal(err)
	}
	if err := manager.UpdateEndpoint(ctx, "peer", "127.0.0.1:4567"); err != nil {
		t.Fatal(err)
	}
	if err := manager.RemovePeer(ctx, "peer"); err != nil {
		t.Fatal(err)
	}
	if err := manager.Down(ctx); err != nil {
		t.Fatal(err)
	}
	if runner.installed {
		t.Fatal("tunnel service still installed")
	}
	if _, err := os.Stat(runner.confPath); !os.IsNotExist(err) {
		t.Fatal("private tunnel configuration was retained")
	}
}
