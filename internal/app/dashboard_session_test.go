package app

import (
	"crypto/tls"
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Viper-Boss/nknguard/internal/config"
)

func loginTestNode(t *testing.T) *Node {
	t.Helper()
	cfg := config.Default()
	cfg.Paths.StateDir = t.TempDir()
	node, err := OpenNode(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := node.SetDashboardPassword("private dashboard password"); err != nil {
		t.Fatal(err)
	}
	return node
}

func loginTestHandler(t *testing.T, node *Node) http.Handler {
	t.Helper()
	assets, err := fs.Sub(dashboardAssets, "dashboard")
	if err != nil {
		t.Fatal(err)
	}
	return dashboardSessionHandler(node, newLoginThrottle(), "127.0.0.1:7878", assets, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
}

func loginTestRequest(handler http.Handler, method, path, body string, cookie *http.Cookie, origin string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://127.0.0.1:7878"+path, strings.NewReader(body))
	if cookie != nil {
		r.AddCookie(cookie)
	}
	if method == "POST" {
		r.Header.Set("X-NKNGuard-UI", "1")
	}
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}

func loginTestCookie(t *testing.T, handler http.Handler, password string) *http.Cookie {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"username": "admin", "password": password})
	w := loginTestRequest(handler, "POST", "/api/auth/login", string(body), nil, "")
	if w.Code != 200 || len(w.Result().Cookies()) != 1 {
		t.Fatalf("login failed: %d %s", w.Code, w.Body.String())
	}
	return w.Result().Cookies()[0]
}

func TestDashboardWebLoginAndLogout(t *testing.T) {
	node := loginTestNode(t)
	handler := loginTestHandler(t, node)
	w := loginTestRequest(handler, "GET", "/", "", nil, "")
	if w.Code != 303 || w.Header().Get("Location") != "/login" || w.Header().Get("WWW-Authenticate") != "" {
		t.Fatalf("native login challenge: %d %v", w.Code, w.Header())
	}
	for _, path := range []string{"/login", "/login.css", "/login.js"} {
		w := loginTestRequest(handler, "GET", path, "", nil, "")
		if w.Code != 200 {
			t.Fatalf("public login asset %s: %d", path, w.Code)
		}
	}
	for _, path := range []string{"/api/status", "/api/logs", "/api/updates"} {
		w := loginTestRequest(handler, "GET", path, "", nil, "")
		if w.Code != 401 || w.Header().Get("WWW-Authenticate") != "" {
			t.Fatalf("unprotected API %s: %d", path, w.Code)
		}
	}
	r := httptest.NewRequest("GET", "http://127.0.0.1:7878/api/status", nil)
	r.SetBasicAuth("admin", "private dashboard password")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatal("cached browser Basic credentials bypassed session login")
	}
	w = loginTestRequest(handler, "POST", "/api/auth/login", `{"username":"admin","password":"wrong"}`, nil, "")
	if w.Code != 401 || len(w.Result().Cookies()) != 0 {
		t.Fatal("wrong password created session")
	}
	cookie := loginTestCookie(t, handler, "private dashboard password")
	if !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.Path != "/" || cookie.Secure || cookie.MaxAge != 43200 || len(cookie.Value) != 43 {
		t.Fatalf("unsafe cookie: %+v", cookie)
	}
	if loginTestRequest(handler, "GET", "/api/status", "", cookie, "").Code != 204 {
		t.Fatal("session did not authenticate")
	}
	w = loginTestRequest(handler, "GET", "/login", "", cookie, "")
	if w.Code != 303 || w.Header().Get("Location") != "/" {
		t.Fatal("authenticated visitor was not sent to dashboard")
	}
	w = loginTestRequest(handler, "POST", "/api/auth/logout", "", cookie, "")
	if w.Code != 204 || w.Result().Cookies()[0].MaxAge != -1 {
		t.Fatal("logout did not clear cookie")
	}
	if loginTestRequest(handler, "GET", "/api/status", "", cookie, "").Code != 401 {
		t.Fatal("replayed logout cookie accepted")
	}
}

func TestDashboardLoginOriginAndHostProtection(t *testing.T) {
	handler := loginTestHandler(t, loginTestNode(t))
	for _, path := range []string{"/api/auth/login", "/api/auth/logout"} {
		w := loginTestRequest(handler, "POST", path, `{"username":"admin","password":"private dashboard password"}`, nil, "https://attacker.example")
		if w.Code != 403 {
			t.Fatalf("cross-origin %s accepted", path)
		}
		r := httptest.NewRequest("POST", "http://127.0.0.1:7878"+path, strings.NewReader(`{}`))
		w = httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatal("missing action header accepted")
		}
	}
	r := httptest.NewRequest("GET", "http://attacker.example:7878/login", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("invalid host accepted")
	}
	w = loginTestRequest(handler, "POST", "/api/auth/login", strings.Repeat("x", 5000), nil, "")
	if w.Code != 400 {
		t.Fatal("oversized login body accepted")
	}
	w = httptest.NewRecorder()
	r = httptest.NewRequest("POST", "https://127.0.0.1:7878/api/auth/login", strings.NewReader(`{"username":"admin","password":"private dashboard password"}`))
	r.TLS = &tls.ConnectionState{}
	r.Header.Set("X-NKNGuard-UI", "1")
	handler.ServeHTTP(w, r)
	if w.Code != 200 || !w.Result().Cookies()[0].Secure {
		t.Fatal("HTTPS cookie was not secure")
	}
}

func TestDashboardSessionExpiryRotationAndBound(t *testing.T) {
	node := loginTestNode(t)
	sessions := newDashboardSessions()
	now := time.Unix(1800000000, 0)
	sessions.now = func() time.Time { return now }
	credential, err := dashboardCredential(node)
	if err != nil {
		t.Fatal(err)
	}
	value, err := sessions.create(credential)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "http://127.0.0.1:7878/api/status", nil)
	r.AddCookie(&http.Cookie{Name: dashboardCookie, Value: value})
	if !sessions.valid(r, node) {
		t.Fatal("fresh session rejected")
	}
	now = now.Add(dashboardSessionTTL)
	if sessions.valid(r, node) {
		t.Fatal("expired session accepted")
	}
	for i := 0; i < dashboardSessionLimit+1; i++ {
		if _, err := sessions.create(credential); err != nil {
			t.Fatal(err)
		}
	}
	if len(sessions.entries) != dashboardSessionLimit {
		t.Fatal("session table exceeded limit")
	}
	// A CLI process using the same persisted password must invalidate sessions too.
	other, err := OpenNode(node.Config)
	if err != nil {
		t.Fatal(err)
	}
	handler := loginTestHandler(t, node)
	cookie := loginTestCookie(t, handler, "private dashboard password")
	if err := other.SetDashboardPassword("new private dashboard password"); err != nil {
		t.Fatal(err)
	}
	if loginTestRequest(handler, "GET", "/api/status", "", cookie, "").Code != 401 {
		t.Fatal("rotated password left session valid")
	}
	newCookie := loginTestCookie(t, handler, "new private dashboard password")
	if newCookie.Value == cookie.Value {
		t.Fatal("session token reused")
	}
	if loginTestRequest(handler, "GET", "/api/status", "", newCookie, "").Code != 204 {
		t.Fatal("new password cannot authenticate")
	}
}
