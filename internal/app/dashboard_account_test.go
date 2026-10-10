package app

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/Viper-Boss/nknguard/internal/config"
)

func TestDashboardAccountMigrationAndSessionRevocation(t *testing.T) {
	node := loginTestNode(t)
	handler := loginTestHandler(t, node)
	cookie := loginTestCookie(t, handler, "private dashboard password")
	if err := node.SetDashboardAccount("我的NAS", ""); err != nil {
		t.Fatal(err)
	}
	if node.DashboardUsername() != "我的NAS" || !node.VerifyDashboardPassword("private dashboard password") {
		t.Fatal("username migration changed password")
	}
	if node.Keystore.Has(dashboardPasswordName) || node.Keystore.Has(dashboardKeyName) {
		t.Fatal("legacy credential remains")
	}
	if loginTestRequest(handler, "GET", "/api/status", "", cookie, "").Code != 401 {
		t.Fatal("old session survived username change")
	}
	wrong := loginTestRequest(handler, "POST", "/api/auth/login", `{"username":"admin","password":"private dashboard password"}`, nil, "")
	if wrong.Code != 401 {
		t.Fatal("old username still accepted")
	}
	w := loginTestRequest(handler, "POST", "/api/auth/login", `{"username":"我的NAS","password":"private dashboard password"}`, nil, "")
	if w.Code != 200 {
		t.Fatal("new username rejected")
	}
	if err := node.SetDashboardPassword("new private dashboard password"); err != nil {
		t.Fatal(err)
	}
	if node.DashboardUsername() != "我的NAS" || !node.VerifyDashboardPassword("new private dashboard password") {
		t.Fatal("CLI password reset changed username")
	}
	if err := node.ChangeDashboardAccount("private dashboard password", "old-request", "another private password"); err == nil {
		t.Fatal("stale password overwrote updated account")
	}
	longName := strings.Repeat("中", 32)
	if err := node.SetDashboardAccount(longName, ""); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{"username": longName, "password": "new private dashboard password"})
	if loginTestRequest(handler, "POST", "/api/auth/login", string(body), nil, "").Code != 200 {
		t.Fatal("valid Chinese username rejected")
	}
	raw, _ := node.Keystore.ReadSecret(dashboardAccountName)
	if bytes.Contains(raw, []byte("new private dashboard password")) {
		t.Fatal("plaintext password persisted")
	}
	for _, name := range []string{"ab", "bad name", "bad/name", "<admin>", "admin\n"} {
		if ValidateDashboardUsername(name) == nil {
			t.Fatalf("invalid username accepted: %q", name)
		}
	}
}

func TestDashboardFirstRunWizardAndClosedRegistration(t *testing.T) {
	cfg := config.Default()
	cfg.Paths.StateDir = t.TempDir()
	node, err := OpenNode(cfg)
	if err != nil {
		t.Fatal(err)
	}
	seed := bytes.Repeat([]byte{7}, 32)
	if err := node.Keystore.WriteSecret("nkn.seed", seed); err != nil {
		t.Fatal(err)
	}
	device := node.Device.DeviceID()
	handler := loginTestHandler(t, node)
	w := loginTestRequest(handler, "GET", "/", "", nil, "")
	if w.Code != 303 || w.Header().Get("Location") != "/setup" {
		t.Fatal("first run did not open wizard")
	}
	for _, path := range []string{"/setup", "/setup.css", "/setup.js", "/api/setup"} {
		if loginTestRequest(handler, "GET", path, "", nil, "").Code != 200 {
			t.Fatalf("setup unavailable: %s", path)
		}
	}
	if loginTestRequest(handler, "GET", "/api/status", "", nil, "").Code != 401 {
		t.Fatal("unconfigured management API exposed")
	}
	body := `{"username":"nas-owner","password":"private dashboard password","confirm":"private dashboard password"}`
	if loginTestRequest(handler, "POST", "/api/setup", body, nil, "https://attacker.example").Code != 403 {
		t.Fatal("cross-origin setup accepted")
	}
	if loginTestRequest(handler, "POST", "/api/setup", `{"username":"a","password":"short","confirm":"short"}`, nil, "").Code != 400 {
		t.Fatal("bad setup accepted")
	}
	w = loginTestRequest(handler, "POST", "/api/setup", body, nil, "")
	if w.Code != 200 || len(w.Result().Cookies()) != 1 {
		t.Fatalf("wizard registration failed: %d %s", w.Code, w.Body.String())
	}
	var info map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &info); err != nil {
		t.Fatal(err)
	}
	if info["nkn_address"] == "" || info["device_id"] != device {
		t.Fatal("identity preview unavailable")
	}
	if got, _ := node.Keystore.ReadSecret("nkn.seed"); !bytes.Equal(got, seed) {
		t.Fatal("wizard regenerated identity")
	}
	if loginTestRequest(handler, "GET", "/api/status", "", w.Result().Cookies()[0], "").Code != 204 {
		t.Fatal("wizard did not authenticate owner")
	}
	if loginTestRequest(handler, "POST", "/api/setup", body, nil, "").Code != 409 {
		t.Fatal("registration remained open")
	}
	if loginTestRequest(handler, "GET", "/setup", "", nil, "").Code != 303 {
		t.Fatal("configured installation exposed wizard")
	}
	if err := node.SetupDashboardAccount("attacker", "replacement password"); err != ErrDashboardConfigured {
		t.Fatal("existing account overwritten")
	}
}

func TestDashboardAccountChangeNeedsCurrentPassword(t *testing.T) {
	node := loginTestNode(t)
	handler := dashboardAccountChangeHandler(node, newLoginThrottle())
	request := func(body, origin string) int {
		r := loginTestRequest(handler, http.MethodPost, "/api/admin/account", body, nil, origin)
		return r.Code
	}
	if request(`{"username":"nas-owner","current":"wrong","new":""}`, "") != 403 {
		t.Fatal("wrong current password accepted")
	}
	if request(`{"username":"nas-owner","current":"private dashboard password","new":""}`, "https://attacker.example") != 403 {
		t.Fatal("cross-origin account change accepted")
	}
	if request(`{"username":"nas-owner","current":"private dashboard password","new":""}`, "") != 204 {
		t.Fatal("username-only change failed")
	}
	if node.DashboardUsername() != "nas-owner" || !node.VerifyDashboardPassword("private dashboard password") {
		t.Fatal("username-only change damaged account")
	}
}
