package app

import (
	"context"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	qrcode "github.com/skip2/go-qrcode"
)

//go:embed dashboard/*
var dashboardAssets embed.FS

// ServeDashboard exposes a local-only fnOS control panel. A remote browser can
// reach it through an SSH port forward. A reverse proxy must preserve the
// loopback Host and matching Origin; arbitrary forwarded headers are untrusted.
func (d *Daemon) ServeDashboard(ctx context.Context) (io.Closer, error) {
	if !d.Node.DashboardPasswordReady() {
		return nil, errors.New("dashboard password is not configured")
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
	logins := newLoginThrottle()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/support", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, supportAddresses)
	})
	mux.HandleFunc("GET /api/support/qr/{asset}", supportQRHandler())
	mux.HandleFunc("GET /api/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, d.Status(r.Context()))
	})
	mux.HandleFunc("GET /api/logs", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, d.Logs.Lines())
	})
	mux.HandleFunc("POST /api/admin/password", dashboardPasswordChangeHandler(d.Node, logins))
	mux.HandleFunc("GET /api/usage", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()
		writeJSON(w, d.usageStatus(ctx, r.URL.Query().Get("refresh") == "1"))
	})
	mux.HandleFunc("POST /api/usage", func(w http.ResponseWriter, r *http.Request) {
		if !dashboardActionAllowed(r) {
			http.Error(w, "same-origin action required", http.StatusForbidden)
			return
		}
		var request struct {
			Enabled *bool `json:"enabled"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 256)).Decode(&request); err != nil || request.Enabled == nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		if d.Usage == nil {
			http.Error(w, "usage statistics unavailable", http.StatusServiceUnavailable)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		if err := d.Usage.SetEnabled(ctx, *request.Enabled); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, d.usageStatus(ctx, false))
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
			status := http.StatusForbidden
			if errors.Is(err, ErrPairingOffline) {
				status = http.StatusServiceUnavailable
			}
			http.Error(w, err.Error(), status)
			return
		}
		uri, err := invite.URI()
		if err != nil {
			http.Error(w, "encode invitation failed", http.StatusInternalServerError)
			return
		}
		png, err := qrcode.Encode(uri, qrcode.Medium, 768)
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
		if !d.Controller.RequestDirect(ctx, r.PathValue("id")) {
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
			switch ok, retry := dashboardAuthenticated(r, d.Node, logins); {
			case retry > 0:
				tooManyAttempts(w, retry)
				return
			case !ok:
				w.Header().Set("WWW-Authenticate", `Basic realm="NKNGuard NAS"`)
				http.Error(w, "administrator password required", http.StatusUnauthorized)
				return
			}
			mux.ServeHTTP(w, r)
		}),
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      45 * time.Second,
		IdleTimeout:       60 * time.Second,
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

// dashboardAuthenticated checks the Basic credentials. While too many wrong
// passwords have been tried it returns how long to wait instead, without
// checking the password. A request without credentials (a browser's first
// request, before it prompts) is not counted as a failure.
func dashboardAuthenticated(r *http.Request, node *Node, logins *loginThrottle) (bool, time.Duration) {
	user, supplied, ok := r.BasicAuth()
	if !ok {
		return false, 0
	}
	return logins.verify(func() bool {
		return user == "admin" && node.VerifyDashboardPassword(supplied)
	})
}

func tooManyAttempts(w http.ResponseWriter, retry time.Duration) {
	seconds := int((retry + time.Second - 1) / time.Second)
	w.Header().Set("Retry-After", strconv.Itoa(seconds))
	http.Error(w, "too many wrong passwords; try again in "+strconv.Itoa(seconds)+" s", http.StatusTooManyRequests)
}

// Wrong-password throttling. The panel only listens on loopback, so every
// client (SSH forward, fnOS reverse proxy) shares one address and the limit is
// global: after loginFreeFailures consecutive wrong passwords each further
// attempt is refused for a delay that doubles up to loginMaxDelay. A correct
// password resets the count. Checks are serialized so parallel guesses cannot
// slip past the count.
const (
	loginFreeFailures = 5
	loginBaseDelay    = time.Second
	loginMaxDelay     = time.Minute
)

type loginThrottle struct {
	verifyMu sync.Mutex
	now      func() time.Time
	failures int
	until    time.Time
}

func newLoginThrottle() *loginThrottle { return &loginThrottle{now: time.Now} }

// verify runs check unless attempts are currently blocked, and records the
// outcome. It returns the remaining wait when blocked.
func (t *loginThrottle) verify(check func() bool) (bool, time.Duration) {
	t.verifyMu.Lock()
	defer t.verifyMu.Unlock()
	if wait := t.until.Sub(t.now()); wait > 0 {
		return false, wait
	}
	if check() {
		t.failures = 0
		t.until = time.Time{}
		return true, 0
	}
	t.failures++
	if extra := t.failures - loginFreeFailures; extra >= 0 {
		delay := loginMaxDelay
		if extra < 6 {
			delay = min(loginBaseDelay<<extra, loginMaxDelay)
		}
		t.until = t.now().Add(delay)
	}
	return false, 0
}

func dashboardPasswordChangeHandler(node *Node, logins *loginThrottle) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !dashboardActionAllowed(r) {
			http.Error(w, "same-origin action required", http.StatusForbidden)
			return
		}
		var request struct {
			Current string `json:"current"`
			New     string `json:"new"`
		}
		decoder := json.NewDecoder(io.LimitReader(r.Body, 4096))
		if err := decoder.Decode(&request); err != nil {
			http.Error(w, "invalid password request", http.StatusBadRequest)
			return
		}
		ok, retry := logins.verify(func() bool { return node.VerifyDashboardPassword(request.Current) })
		if retry > 0 {
			tooManyAttempts(w, retry)
			return
		}
		if !ok {
			http.Error(w, "current password is incorrect", http.StatusForbidden)
			return
		}
		if err := node.SetDashboardPassword(request.New); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
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
