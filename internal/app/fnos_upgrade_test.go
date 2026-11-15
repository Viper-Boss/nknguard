package app

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestFnosUpgradeRequiresNativeTaskAndActualVersion(t *testing.T) {
	for _, scenario := range []string{"success", "noop-old-version", "wrong-app", "wizard", "missing-code", "failed-task"} {
		t.Run(scenario, func(t *testing.T) {
			submissions := 0
			recorded := ""
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var req map[string]any
				_ = json.NewDecoder(r.Body).Decode(&req)
				var data any
				code := 0
				switch r.URL.Path {
				case "/rpc/v1/update/info":
					if len(req) == 0 {
						if scenario == "missing-code" {
							w.Write([]byte(`{"data":{}}`))
							return
						}
						code = 10030
						break
					}
					data = map[string]any{"wizardInfo": map[string]any{"installedVolumeID": 1, "hasWizard": scenario == "wizard"}}
				case "/rpc/v1/download/task":
					data = map[string]any{"downloadTaskId": "download-1"}
				case "/rpc/v1/download/status":
					name := "nknguard"
					if scenario == "wrong-app" {
						name = "different-app"
					}
					data = map[string]any{"status": 2, "appName": name, "version": "0.2.22", "packageType": "path", "installed": true}
				case "/rpc/v1/update/task":
					submissions++
					if req["appName"] != "nknguard" || req["updateVersion"] != "0.2.22" {
						t.Error("wrong upgrade identity")
					}
					sys, _ := req["systemParameters"].(map[string]any)
					if sys["installVolumeID"] != float64(1) || sys["dataVolumeId"] != float64(1) {
						t.Error("existing volume not preserved")
					}
					data = map[string]any{"taskId": "upgrade-1"}
				case "/rpc/v1/common/status":
					status := 2
					if scenario == "failed-task" {
						status = 3
					}
					data = map[string]any{"status": status, "message": "fixture"}
				default:
					t.Error("unexpected route", r.URL.Path)
				}
				json.NewEncoder(w).Encode(map[string]any{"code": code, "msg": "", "data": data})
			}))
			defer server.Close()
			c := &fnosUpgradeClient{http: &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
			}}}, interval: time.Millisecond,
				installed: func() (string, error) {
					if scenario == "noop-old-version" {
						return "0.2.19", nil
					}
					return "0.2.22", nil
				}, running: func(context.Context) (string, error) {
					if scenario == "noop-old-version" {
						return "v0.2.19", nil
					}
					return "v0.2.22", nil
				}}
			defer c.http.CloseIdleConnections()
			ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
			defer cancel()
			err := c.upgrade(ctx, "/private/verified.fpk", "v0.2.22", func(id string) { recorded = id })
			if scenario == "success" {
				if err != nil || submissions != 1 || recorded != "upgrade-1" {
					t.Fatalf("upgrade failed: %v %d %s", err, submissions, recorded)
				}
			} else if err == nil {
				t.Fatal("unverified upgrade reported success")
			}
			if (scenario == "wrong-app" || scenario == "wizard" || scenario == "missing-code") && submissions != 0 {
				t.Fatal("unsafe package was submitted")
			}
		})
	}
}

func TestResumeActiveUpdateAcrossDaemonRestart(t *testing.T) {
	// Expiry prevents a crashed helper's stale task from blocking future updates forever.
	for _, tc := range []struct {
		state string
		age   time.Duration
		want  bool
	}{{"installing", time.Minute, true}, {"verifying", time.Minute, true}, {"complete", time.Minute, false}, {"installing", time.Hour, false}} {
		if got := activeUpdateJob(tc.state, time.Now().Add(-tc.age)); got != tc.want {
			t.Fatalf("%s %s: %v", tc.state, tc.age, got)
		}
	}
	if sameUpdateVersion("v0.2.22", "0.2.19") {
		t.Fatal("old version accepted")
	}
	if !sameUpdateVersion("v0.2.22", "0.2.22") {
		t.Fatal("v prefix not normalized")
	}
}
