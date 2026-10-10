package app

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"strings"
	"sync"
	"time"
)

const dashboardCookie = "nknguard_session"
const dashboardSessionTTL = 12 * time.Hour
const dashboardSessionLimit = 128

type dashboardSession struct {
	expires    time.Time
	credential [32]byte
}

// Sessions are bounded, opaque and memory-only. Restarting the daemon logs out
// browsers; changing the stored password invalidates all existing sessions,
// including when the change came from the CLI in another process.
type dashboardSessions struct {
	mu      sync.Mutex
	entries map[[32]byte]dashboardSession
	now     func() time.Time
}

func newDashboardSessions() *dashboardSessions {
	return &dashboardSessions{entries: make(map[[32]byte]dashboardSession), now: time.Now}
}

func dashboardCredential(node *Node) ([32]byte, error) {
	raw, err := node.Keystore.ReadSecret(dashboardPasswordName)
	if errors.Is(err, fs.ErrNotExist) {
		raw, err = node.Keystore.ReadSecret(dashboardKeyName)
	}
	return sha256.Sum256(raw), err
}

func (s *dashboardSessions) create(credential [32]byte) (string, error) {
	var token [32]byte
	if _, err := rand.Read(token[:]); err != nil {
		return "", err
	}
	value := base64.RawURLEncoding.EncodeToString(token[:])
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for key, session := range s.entries {
		if !now.Before(session.expires) {
			delete(s.entries, key)
		}
	}
	if len(s.entries) >= dashboardSessionLimit {
		var oldest [32]byte
		var expiry time.Time
		for key, session := range s.entries {
			if expiry.IsZero() || session.expires.Before(expiry) {
				oldest, expiry = key, session.expires
			}
		}
		delete(s.entries, oldest)
	}
	s.entries[sha256.Sum256([]byte(value))] = dashboardSession{expires: now.Add(dashboardSessionTTL), credential: credential}
	return value, nil
}

func (s *dashboardSessions) remove(r *http.Request) {
	if cookie, err := r.Cookie(dashboardCookie); err == nil {
		s.mu.Lock()
		delete(s.entries, sha256.Sum256([]byte(cookie.Value)))
		s.mu.Unlock()
	}
}

func (s *dashboardSessions) valid(r *http.Request, node *Node) bool {
	cookie, err := r.Cookie(dashboardCookie)
	if err != nil || len(cookie.Value) != 43 {
		return false
	}
	key := sha256.Sum256([]byte(cookie.Value))
	s.mu.Lock()
	session, ok := s.entries[key]
	s.mu.Unlock()
	if !ok {
		return false
	}
	credential, err := dashboardCredential(node)
	if err != nil || !s.now().Before(session.expires) || credential != session.credential {
		s.remove(r)
		return false
	}
	return true
}

func setDashboardCookie(w http.ResponseWriter, r *http.Request, value string) {
	cookie := &http.Cookie{Name: dashboardCookie, Value: value, Path: "/", HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode, MaxAge: int(dashboardSessionTTL.Seconds())}
	if value == "" {
		cookie.MaxAge = -1
		cookie.Expires = time.Unix(1, 0)
	}
	http.SetCookie(w, cookie)
}

func dashboardSessionHandler(node *Node, logins *loginThrottle, listen string, assets fs.FS, protected http.Handler) http.Handler {
	sessions := newDashboardSessions()
	files := http.FileServer(http.FS(assets))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !validDashboardHost(r.Host, listen) {
			http.Error(w, "invalid host", http.StatusForbidden)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
		path := r.URL.Path
		if path == "/api/auth/login" {
			if r.Method != http.MethodPost {
				w.Header().Set("Allow", "POST")
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			if !dashboardActionAllowed(r) {
				http.Error(w, "same-origin action required", http.StatusForbidden)
				return
			}
			var credentials struct {
				Username string `json:"username"`
				Password string `json:"password"`
			}
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&credentials); err != nil || len(credentials.Username) > 64 || len(credentials.Password) > 72 {
				http.Error(w, "登录信息格式不正确", http.StatusBadRequest)
				return
			}
			credential, credentialErr := dashboardCredential(node)
			ok, retry := logins.verify(func() bool {
				return credentialErr == nil && credentials.Username == "admin" && node.VerifyDashboardPassword(credentials.Password)
			})
			if retry > 0 {
				tooManyAttempts(w, retry)
				return
			}
			currentCredential, currentErr := dashboardCredential(node)
			if !ok || currentErr != nil || credential != currentCredential {
				http.Error(w, "用户名或密码不正确，请重试", http.StatusUnauthorized)
				return
			}
			value, err := sessions.create(credential)
			if err != nil {
				http.Error(w, "无法建立登录会话，请稍后重试", http.StatusInternalServerError)
				return
			}
			sessions.remove(r)
			setDashboardCookie(w, r, value)
			writeJSON(w, map[string]bool{"ok": true})
			return
		}
		if path == "/api/auth/logout" {
			if r.Method != http.MethodPost || !dashboardActionAllowed(r) {
				http.Error(w, "same-origin POST required", http.StatusForbidden)
				return
			}
			sessions.remove(r)
			setDashboardCookie(w, r, "")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if path == "/login.css" || path == "/login.js" {
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			files.ServeHTTP(w, r)
			return
		}
		authenticated := sessions.valid(r, node)
		if path == "/login" || path == "/login.html" {
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			if authenticated {
				http.Redirect(w, r, "/", http.StatusSeeOther)
				return
			}
			raw, err := fs.ReadFile(assets, "login.html")
			if err != nil {
				http.Error(w, "login page unavailable", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			http.ServeContent(w, r, "login.html", time.Time{}, bytes.NewReader(raw))
			return
		}
		if !authenticated {
			if strings.HasPrefix(path, "/api/") {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte("请登录管理后台"))
			} else {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
			}
			return
		}
		protected.ServeHTTP(w, r)
	})
}
