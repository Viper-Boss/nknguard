//go:build windows

package app

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWindowsPipeLongUnicodePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), strings.Repeat("中文目录", 50), "control.sock")
	name, err := localPipeName(path)
	if err != nil || len(name) > 100 {
		t.Fatalf("endpoint %q: %v", name, err)
	}
	l, err := listenLocalAPI(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		c, e := l.Accept()
		if e == nil {
			defer c.Close()
			io.Copy(c, c)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c, err := dialLocalAPI(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	c.Write([]byte("echo"))
	buf := make([]byte, 4)
	if _, err = io.ReadFull(c, buf); err != nil || string(buf) != "echo" {
		t.Fatalf("pipe: %q %v", buf, err)
	}
	if _, err = listenLocalAPI(path); err == nil {
		t.Fatal("duplicate listener accepted")
	}
}
func TestWindowsPipeLegacyDaemonFallback(t *testing.T) {
	// A deliberately short relative legacy socket is used to exercise upgrades.
	path := filepath.Join(t.TempDir(), "api.sock")
	if len(path) > 100 {
		t.Skip("legacy AF_UNIX path too long in this test environment")
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		c, e := l.Accept()
		if e == nil {
			c.Write([]byte("old"))
			c.Close()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c, err := dialLocalAPI(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	b := make([]byte, 3)
	if _, err = io.ReadFull(c, b); err != nil || string(b) != "old" {
		t.Fatal(err, string(b))
	}
}

// Used by the maintainer to verify medium-integrity GUI -> elevated daemon.
func TestLiveWindowsPipeElevation(t *testing.T) {
	role := os.Getenv("NKG_PIPE_ROLE")
	if role == "" {
		t.Skip("opt-in cross-elevation check")
	}
	path := os.Getenv("NKG_PIPE_PATH")
	if role == "server" {
		l, err := listenLocalAPI(path)
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		done := make(chan struct{})
		mux := http.NewServeMux()
		mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"version":"pipe-test"}`))
			go func() { time.Sleep(200 * time.Millisecond); close(done) }()
		})
		srv := &http.Server{Handler: mux}
		defer srv.Close()
		go srv.Serve(l)
		if err = os.WriteFile(os.Getenv("NKG_PIPE_READY"), []byte("ready"), 0600); err != nil {
			t.Fatal(err)
		}
		select {
		case <-done:
		case <-time.After(45 * time.Second):
			t.Fatal("ordinary GUI did not connect")
		}
		return
	}
	status, err := NewClient(path).Status()
	if err != nil || status.Version != "pipe-test" {
		t.Fatalf("cross-elevation: %+v %v", status, err)
	}
}
