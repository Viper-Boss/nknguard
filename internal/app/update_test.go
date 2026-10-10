package app

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDashboardUpdateActionsRequireSameOrigin(t *testing.T) {
	d := &Daemon{}
	mux := http.NewServeMux()
	d.registerUpdates(mux)
	for _, route := range []string{"/api/updates/check", "/api/updates/upload"} {
		for _, tc := range []struct{ origin, header, site string }{{"", "", ""}, {"https://evil.example", "1", ""}, {"", "1", "cross-site"}} {
			r := httptest.NewRequest("POST", "http://127.0.0.1:7878"+route, nil)
			r.Header.Set("Origin", tc.origin)
			r.Header.Set("X-NKNGuard-UI", tc.header)
			r.Header.Set("Sec-Fetch-Site", tc.site)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, r)
			if w.Code != http.StatusForbidden {
				t.Fatalf("%s accepted cross-origin action: %d", route, w.Code)
			}
		}
	}
}
