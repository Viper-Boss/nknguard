package app

import (
	"bytes"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Viper-Boss/nknguard/internal/config"
)

func TestDashboardPasswordMigrationAndAuthentication(t *testing.T) {
	cfg := config.Default()
	cfg.Paths.StateDir = t.TempDir()
	first, err := OpenNode(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if first.DashboardPasswordReady() {
		t.Fatal("unconfigured dashboard accepted")
	}
	if err := first.Keystore.WriteSecret(dashboardKeyName, []byte("legacy-password")); err != nil {
		t.Fatal(err)
	}
	if !first.VerifyDashboardPassword("legacy-password") {
		t.Fatal("legacy password rejected")
	}
	password := "correct horse battery staple"
	if err := first.SetDashboardPassword(password); err != nil {
		t.Fatal(err)
	}
	if first.VerifyDashboardPassword("legacy-password") {
		t.Fatal("legacy password still accepted")
	}
	if _, err := os.Stat(filepath.Join(cfg.KeystoreDir(), dashboardKeyName)); !os.IsNotExist(err) {
		t.Fatalf("legacy key remains: %v", err)
	}
	hash, err := first.Keystore.ReadSecret(dashboardPasswordName)
	if err != nil || bytes.Contains(hash, []byte(password)) {
		t.Fatal("plaintext dashboard password was persisted")
	}
	again, err := OpenNode(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !again.VerifyDashboardPassword(password) {
		t.Fatal("dashboard password hash was not persisted")
	}
	logins := newLoginThrottle()
	r := httptest.NewRequest("GET", "http://127.0.0.1:7878/api/status", nil)
	if ok, _ := dashboardAuthenticated(r, again, logins); ok {
		t.Fatal("missing authentication accepted")
	}
	r.SetBasicAuth("admin", "wrong")
	if ok, _ := dashboardAuthenticated(r, again, logins); ok {
		t.Fatal("wrong password accepted")
	}
	r.SetBasicAuth("admin", password)
	if ok, _ := dashboardAuthenticated(r, again, logins); !ok {
		t.Fatal("correct password rejected")
	}
}

func TestDashboardPasswordChangeHandler(t *testing.T) {
	cfg := config.Default()
	cfg.Paths.StateDir = t.TempDir()
	node, err := OpenNode(cfg)
	if err != nil {
		t.Fatal(err)
	}
	oldPassword := "correct horse battery staple"
	newPassword := "another private passphrase"
	if err := node.SetDashboardPassword(oldPassword); err != nil {
		t.Fatal(err)
	}
	post := func(body string, sameOrigin bool) int {
		t.Helper()
		r := httptest.NewRequest("POST", "http://127.0.0.1:7878/api/admin/password", strings.NewReader(body))
		if sameOrigin {
			r.Header.Set("X-NKNGuard-UI", "1")
		}
		w := httptest.NewRecorder()
		dashboardPasswordChangeHandler(node, newLoginThrottle())(w, r)
		return w.Code
	}
	if code := post(`{"current":"correct horse battery staple","new":"another private passphrase"}`, false); code != 403 {
		t.Fatalf("cross-origin action accepted: %d", code)
	}
	if code := post(`{"current":"wrong","new":"another private passphrase"}`, true); code != 403 {
		t.Fatalf("wrong current password accepted: %d", code)
	}
	if code := post(`{"current":"correct horse battery staple","new":"short"}`, true); code != 400 {
		t.Fatalf("short password accepted: %d", code)
	}
	if code := post(`{"current":"correct horse battery staple","new":"another private passphrase"}`, true); code != 204 {
		t.Fatalf("password change failed: %d", code)
	}
	if node.VerifyDashboardPassword(oldPassword) || !node.VerifyDashboardPassword(newPassword) {
		t.Fatal("password change did not take effect")
	}
}

func TestDashboardPasswordRemovesLegacySetupNote(t *testing.T) {
	cfg := config.Default()
	cfg.Paths.StateDir = t.TempDir()
	cfg.Paths.LegacySetupNote = filepath.Join(t.TempDir(), "first-run.txt")
	if err := os.WriteFile(cfg.Paths.LegacySetupNote, []byte("old generated password\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	node, err := OpenNode(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := node.SetDashboardPassword("short"); err == nil {
		t.Fatal("short password accepted")
	}
	if _, err := os.Stat(cfg.Paths.LegacySetupNote); err != nil {
		t.Fatalf("setup note removed although no password was set: %v", err)
	}
	if err := node.SetDashboardPassword("correct horse battery staple"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(cfg.Paths.LegacySetupNote); !os.IsNotExist(err) {
		t.Fatalf("legacy setup note remains: %v", err)
	}
	// Setting it again with the note already gone is not an error.
	if err := node.SetDashboardPassword("another private passphrase"); err != nil {
		t.Fatal(err)
	}
}

func TestLoginThrottle(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	logins := &loginThrottle{now: func() time.Time { return now }}
	checks := 0
	attempt := func(correct bool) (bool, time.Duration) {
		return logins.verify(func() bool { checks++; return correct })
	}
	for i := 0; i < loginFreeFailures-1; i++ {
		if ok, wait := attempt(false); ok || wait != 0 {
			t.Fatalf("failure %d: ok=%v wait=%v", i+1, ok, wait)
		}
	}
	if ok, wait := attempt(false); ok || wait != 0 {
		t.Fatalf("last free failure: ok=%v wait=%v", ok, wait)
	}
	// Blocked: even the correct password is not checked.
	before := checks
	if ok, wait := attempt(true); ok || wait != loginBaseDelay {
		t.Fatalf("blocked attempt: ok=%v wait=%v", ok, wait)
	}
	if checks != before {
		t.Fatal("password checked while blocked")
	}
	// The delay doubles with every further failure and is capped.
	want := loginBaseDelay
	for i := 0; i < 10; i++ {
		now = now.Add(time.Hour)
		if _, wait := attempt(false); wait != 0 {
			t.Fatalf("attempt after delay refused: %v", wait)
		}
		want = min(want*2, loginMaxDelay)
		if _, wait := attempt(false); wait != want {
			t.Fatalf("delay after %d extra failures = %v, want %v", i+1, wait, want)
		}
	}
	// A correct password after the delay resets the count.
	now = now.Add(time.Hour)
	if ok, _ := attempt(true); !ok {
		t.Fatal("correct password refused after delay")
	}
	for i := 0; i < loginFreeFailures-1; i++ {
		if _, wait := attempt(false); wait != 0 {
			t.Fatal("count not reset by a correct password")
		}
	}
}

func TestDashboardPasswordChangeThrottled(t *testing.T) {
	cfg := config.Default()
	cfg.Paths.StateDir = t.TempDir()
	node, err := OpenNode(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := node.SetDashboardPassword("correct horse battery staple"); err != nil {
		t.Fatal(err)
	}
	handler := dashboardPasswordChangeHandler(node, newLoginThrottle())
	post := func(current string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "http://127.0.0.1:7878/api/admin/password",
			strings.NewReader(`{"current":"`+current+`","new":"another private passphrase"}`))
		r.Header.Set("X-NKNGuard-UI", "1")
		w := httptest.NewRecorder()
		handler(w, r)
		return w
	}
	for i := 0; i < loginFreeFailures; i++ {
		if w := post("wrong"); w.Code != 403 {
			t.Fatalf("wrong password %d: %d", i+1, w.Code)
		}
	}
	w := post("correct horse battery staple")
	if w.Code != 429 || w.Header().Get("Retry-After") == "" {
		t.Fatalf("throttled change: %d %q", w.Code, w.Header().Get("Retry-After"))
	}
	if !node.VerifyDashboardPassword("correct horse battery staple") {
		t.Fatal("password changed while throttled")
	}
}
