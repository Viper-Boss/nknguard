package app

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Viper-Boss/nknguard/internal/config"
	"github.com/Viper-Boss/nknguard/pkg/mesh"
	"github.com/Viper-Boss/nknguard/pkg/signaling"
	"github.com/Viper-Boss/nknguard/pkg/wireguard"
)

type stubWG struct{ wireguard.Manager }

func (stubWG) Status(context.Context) wireguard.Status {
	return wireguard.Status{State: wireguard.StateUp, Interface: "nkg0"}
}

func TestLogRingKeepsNewestAndRedacts(t *testing.T) {
	ring := NewLogRing(3)
	for _, line := range []string{"one", "two", "three", "four private_key=abcdef"} {
		_, _ = ring.Write([]byte(line + "\n"))
	}
	lines := ring.Lines()
	if len(lines) != 3 || lines[0] != "two" {
		t.Fatalf("ring: %q", lines)
	}
	if strings.Contains(lines[2], "abcdef") {
		t.Fatal("secret reached the log ring")
	}
}

func TestLocalAPI(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Paths.StateDir = filepath.Join(dir, "state")
	cfg.Paths.Socket = filepath.Join(dir, "run", "nknguard.sock")
	node, err := OpenNode(cfg)
	if err != nil {
		t.Fatal(err)
	}
	networkID, _, err := node.CreateNetwork()
	if err != nil {
		t.Fatal(err)
	}
	controller := mesh.New()
	controller.Config.NetworkID = networkID
	controller.Device = node.Device
	controller.Signaling = signaling.NewSwitch().Attach(node.Device.DeviceID())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stopped := make(chan struct{})
	daemon := &Daemon{
		Config: cfg, Node: node, Controller: controller, WireGuard: stubWG{},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Logs: NewLogRing(10), Started: time.Now(),
		down: func() { close(stopped) },
	}
	closer, err := daemon.ServeAPI(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer closer.Close()

	client := NewClient(cfg.Paths.Socket)
	status, err := client.Status()
	if err != nil {
		t.Fatal(err)
	}
	if status.DeviceID != node.Device.DeviceID() || status.NetworkID != networkID || status.WireGuard.State != wireguard.StateUp {
		t.Fatalf("status: %+v", status)
	}
	if err := client.Reconnect("nkg_nobody"); err == nil {
		t.Fatal("reconnect to an unknown peer succeeded")
	}

	var bundle bytes.Buffer
	if err := client.Diagnostics(&bundle); err != nil {
		t.Fatal(err)
	}
	secret, _ := node.JoinSecret()
	gz, err := gzip.NewReader(&bundle)
	if err != nil {
		t.Fatal(err)
	}
	archive := tar.NewReader(gz)
	members := 0
	for {
		_, err := archive.Next()
		if err == io.EOF {
			break
		}
		body, _ := io.ReadAll(archive)
		if strings.Contains(string(body), secret) {
			t.Fatal("join secret in the diagnostics bundle")
		}
		members++
	}
	if members != 4 {
		t.Fatalf("bundle has %d members", members)
	}

	if err := client.Down(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("down did not stop the daemon")
	}
}
