package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Viper-Boss/nknguard/pkg/diagnostics"
	"github.com/Viper-Boss/nknguard/pkg/mesh"
)

// The local API is a Unix socket, owner root, mode 0660. There is no TCP
// listener anywhere in the daemon, so "the management API is exposed on
// 0.0.0.0" is not a configuration mistake anyone can make (spec §36, §67.10).

// SocketMode is the socket's permission.
const SocketMode = 0o660

// ServeAPI starts the local API.
func (d *Daemon) ServeAPI(ctx context.Context) (io.Closer, error) {
	path := d.Config.Paths.Socket
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	// A stale socket from a crashed daemon would make Listen fail. Only a
	// socket is removed — never a regular file someone put at that path.
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSocket != 0 {
		_ = os.Remove(path)
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("local API: %w", err)
	}
	if err := os.Chmod(path, SocketMode); err != nil {
		_ = listener.Close()
		return nil, err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, d.Status(r.Context())) })
	mux.HandleFunc("GET /v1/peers", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, d.Controller.Peers()) })
	mux.HandleFunc("POST /v1/peers/{id}/reconnect", func(w http.ResponseWriter, r *http.Request) {
		if !d.Controller.Reconnect(r.PathValue("id")) {
			http.Error(w, "unknown peer", http.StatusNotFound)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	})
	mux.HandleFunc("POST /v1/network/down", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]bool{"ok": true})
		go d.Stop()
	})
	mux.HandleFunc("GET /v1/diagnostics", func(w http.ResponseWriter, r *http.Request) {
		var buffer bytes.Buffer
		err := diagnostics.WriteBundle(&buffer, diagnostics.BundleInput{
			Status: d.Status(r.Context()),
			Report: Doctor(r.Context(), d.Config),
			Config: d.Config.Render(),
			Logs:   d.Logs.Lines(),
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/gzip")
		_, _ = w.Write(buffer.Bytes())
	})
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = server.Serve(listener) }()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	return closerFunc(func() error {
		err := server.Close()
		_ = os.Remove(path)
		return err
	}), nil
}

type closerFunc func() error

func (f closerFunc) Close() error { return f() }

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	_ = encoder.Encode(value)
}

// Client talks to a running daemon.
type Client struct {
	http *http.Client
}

// ErrDaemonNotRunning means nothing answered on the socket.
var ErrDaemonNotRunning = errors.New("the nknguard daemon is not running (start it with `sudo nknguard up`)")

// NewClient returns a client for the socket at path.
func NewClient(path string) *Client {
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var dialer net.Dialer
		return dialer.DialContext(ctx, "unix", path)
	}}
	return &Client{http: &http.Client{Transport: transport, Timeout: 30 * time.Second}}
}

func (c *Client) do(method, route string) (*http.Response, error) {
	request, err := http.NewRequest(method, "http://nknguard"+route, nil)
	if err != nil {
		return nil, err
	}
	response, err := c.http.Do(request)
	if err != nil {
		var opErr *net.OpError
		if errors.As(err, &opErr) || strings.Contains(err.Error(), "no such file") || strings.Contains(err.Error(), "connection refused") {
			return nil, ErrDaemonNotRunning
		}
		return nil, err
	}
	if response.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		_ = response.Body.Close()
		return nil, fmt.Errorf("daemon: %s: %s", response.Status, strings.TrimSpace(string(body)))
	}
	return response, nil
}

// Status fetches the node status.
func (c *Client) Status() (diagnostics.Status, error) {
	var status diagnostics.Status
	return status, c.getJSON("/v1/status", &status)
}

// Peers fetches the peer table.
func (c *Client) Peers() ([]mesh.Snapshot, error) {
	var peers []mesh.Snapshot
	return peers, c.getJSON("/v1/peers", &peers)
}

// Reconnect forces a direct attempt.
func (c *Client) Reconnect(deviceID string) error {
	response, err := c.do(http.MethodPost, "/v1/peers/"+deviceID+"/reconnect")
	if err == nil {
		_ = response.Body.Close()
	}
	return err
}

// Down stops the daemon.
func (c *Client) Down() error {
	response, err := c.do(http.MethodPost, "/v1/network/down")
	if err == nil {
		_ = response.Body.Close()
	}
	return err
}

// Diagnostics streams the bundle to w.
func (c *Client) Diagnostics(w io.Writer) error {
	response, err := c.do(http.MethodGet, "/v1/diagnostics")
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, err = io.Copy(w, response.Body)
	return err
}

func (c *Client) getJSON(route string, target any) error {
	response, err := c.do(http.MethodGet, route)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	return json.NewDecoder(response.Body).Decode(target)
}
