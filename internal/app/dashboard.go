package app

import (
	"context"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"io"
	"io/fs"
	"net"
	"net/http"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"
)

//go:embed dashboard/*
var dashboardAssets embed.FS

// ServeDashboard exposes a local-only fnOS control panel. A remote browser can
// reach it through an authenticated fnOS reverse proxy or an SSH port forward.
func (d *Daemon) ServeDashboard(ctx context.Context) (io.Closer, error) {
	adminKey, err := d.Node.DashboardKey()
	if err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp", d.Config.Dashboard.Listen)
	if err != nil {
		return nil, err
	}
	assets, err := fs.Sub(dashboardAssets, "dashboard")
	if err != nil {
		_ = listener.Close()
		return nil, err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, d.Status(r.Context()))
	})
	mux.HandleFunc("GET /api/logs", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, d.Logs.Lines())
	})
	mux.HandleFunc("GET /api/pair/state", func(w http.ResponseWriter, r *http.Request) {
		current, err := d.Node.State.LoadMembership()
		if err != nil {
			http.Error(w, "state unavailable", http.StatusInternalServerError)
			return
		}
		pending := []PendingPair{}
		if d.Pairing != nil {
			pending = d.Pairing.Pending()
		}
		writeJSON(w, map[string]any{"is_owner": current.IsOwner, "approved": current.Members, "pending": pending})
	})
	mux.HandleFunc("POST /api/pair/invite", func(w http.ResponseWriter, r *http.Request) {
		if !dashboardActionAllowed(r) {
			http.Error(w, "same-origin action required", http.StatusForbidden)
			return
		}
		if d.Pairing == nil {
			http.Error(w, "pairing unavailable", http.StatusServiceUnavailable)
			return
		}
		invite, err := d.Pairing.NewInvite()
		if err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		uri, err := invite.URI()
		if err != nil {
			http.Error(w, "encode invitation failed", http.StatusInternalServerError)
			return
		}
		png, err := qrcode.Encode(uri, qrcode.Medium, 320)
		if err != nil {
			http.Error(w, "QR generation failed", http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]any{"uri": uri, "qr_data_url": "data:image/png;base64," + base64.StdEncoding.EncodeToString(png), "expires_at": invite.ExpiresAt})
	})
	mux.HandleFunc("POST /api/pair/{id}/approve", func(w http.ResponseWriter, r *http.Request) {
		if !dashboardActionAllowed(r) {
			http.Error(w, "same-origin action required", http.StatusForbidden)
			return
		}
		if d.Pairing == nil {
			http.Error(w, "pairing unavailable", http.StatusServiceUnavailable)
			return
		}
		if err := d.Pairing.Approve(r.Context(), r.PathValue("id")); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	})
	mux.HandleFunc("POST /api/pair/{id}/revoke", func(w http.ResponseWriter, r *http.Request) {
		if !dashboardActionAllowed(r) {
			http.Error(w, "same-origin action required", http.StatusForbidden)
			return
		}
		if d.Pairing == nil {
			http.Error(w, "pairing unavailable", http.StatusServiceUnavailable)
			return
		}
		if err := d.Pairing.Revoke(r.Context(), r.PathValue("id")); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	})
	mux.HandleFunc("POST /api/peers/{id}/reconnect", func(w http.ResponseWriter, r *http.Request) {
		if !dashboardActionAllowed(r) {
			http.Error(w, "same-origin action required", http.StatusForbidden)
			return
		}
		if !d.Controller.Reconnect(r.PathValue("id")) {
			http.Error(w, "unknown peer", http.StatusNotFound)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	})
	mux.Handle("/", http.FileServer(http.FS(assets)))
	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !validDashboardHost(r.Host, d.Config.Dashboard.Listen) {
				http.Error(w, "invalid host", http.StatusForbidden)
				return
			}
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("Content-Security-Policy", "default-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'")
			if !dashboardAuthenticated(r, adminKey) {
				w.Header().Set("WWW-Authenticate", `Basic realm="NKNGuard NAS"`)
				http.Error(w, "administrator password required", http.StatusUnauthorized)
				return
			}
			mux.ServeHTTP(w, r)
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = server.Serve(listener) }()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	return closerFunc(server.Close), nil
}

func dashboardAuthenticated(r *http.Request, adminKey string) bool {
	user, supplied, ok := r.BasicAuth()
	return ok && user == "admin" && subtle.ConstantTimeCompare([]byte(supplied), []byte(adminKey)) == 1
}

func dashboardActionAllowed(r *http.Request) bool {
	return r.Header.Get("X-NKNGuard-UI") == "1" && sameOrigin(r)
}

func sameOrigin(r *http.Request) bool {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" {
		return false
	}
	origin := r.Header.Get("Origin")
	return origin == "" || origin == "http://"+r.Host || origin == "https://"+r.Host
}

func validDashboardHost(hostPort, listen string) bool {
	host, port, err := net.SplitHostPort(hostPort)
	if err != nil {
		return false
	}
	_, listenPort, err := net.SplitHostPort(listen)
	if err != nil || port != listenPort {
		return false
	}
	return strings.EqualFold(host, "localhost") || net.ParseIP(host).IsLoopback()
}
