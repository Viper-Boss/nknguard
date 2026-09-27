package app

import (
	"bytes"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
	r := httptest.NewRequest("GET", "http://127.0.0.1:7878/api/status", nil)
	if dashboardAuthenticated(r, again) {
		t.Fatal("missing authentication accepted")
	}
	r.SetBasicAuth("admin", "wrong")
	if dashboardAuthenticated(r, again) {
		t.Fatal("wrong password accepted")
	}
	r.SetBasicAuth("admin", password)
	if !dashboardAuthenticated(r, again) {
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
		dashboardPasswordChangeHandler(node)(w, r)
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
