package app

import (
	"net/http/httptest"
	"testing"

	"github.com/Viper-Boss/nknguard/internal/config"
)

func TestDashboardKeyAndAuthentication(t *testing.T) {
	cfg := config.Default()
	cfg.Paths.StateDir = t.TempDir()
	first, err := OpenNode(cfg)
	if err != nil {
		t.Fatal(err)
	}
	key, err := first.DashboardKey()
	if err != nil || len(key) < 40 {
		t.Fatalf("key: %q %v", key, err)
	}
	again, err := OpenNode(cfg)
	if err != nil {
		t.Fatal(err)
	}
	reloaded, err := again.DashboardKey()
	if err != nil || reloaded != key {
		t.Fatal("dashboard key was not persisted")
	}
	r := httptest.NewRequest("GET", "http://127.0.0.1:7878/api/status", nil)
	if dashboardAuthenticated(r, key) {
		t.Fatal("missing authentication accepted")
	}
	r.SetBasicAuth("admin", "wrong")
	if dashboardAuthenticated(r, key) {
		t.Fatal("wrong password accepted")
	}
	r.SetBasicAuth("admin", key)
	if !dashboardAuthenticated(r, key) {
		t.Fatal("correct password rejected")
	}
}
