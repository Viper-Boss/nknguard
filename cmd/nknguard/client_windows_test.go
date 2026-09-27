//go:build windows

package main

import (
	"net/http/httptest"
	"testing"
)

func TestClientWindowRequiresSessionAndOrigin(t *testing.T) {
	window := &clientWindow{}
	handler := window.serve("test-token", make(chan struct{}, 1))
	req := httptest.NewRequest("GET", "http://127.0.0.1:8888/api/state", nil)
	out := httptest.NewRecorder()
	handler.ServeHTTP(out, req)
	if out.Code != 401 {
		t.Fatalf("untrusted request: %d", out.Code)
	}
	req = httptest.NewRequest("GET", "http://127.0.0.1:8888/?token=test-token", nil)
	out = httptest.NewRecorder()
	handler.ServeHTTP(out, req)
	if out.Code != 303 {
		t.Fatalf("session creation: %d", out.Code)
	}
	cookie := out.Result().Cookies()[0]
	req = httptest.NewRequest("POST", "http://127.0.0.1:8888/api/connect", nil)
	req.AddCookie(cookie)
	out = httptest.NewRecorder()
	handler.ServeHTTP(out, req)
	if out.Code != 403 {
		t.Fatalf("cross-origin action: %d", out.Code)
	}
	req = httptest.NewRequest("GET", "http://untrusted.example:8888/?token=test-token", nil)
	out = httptest.NewRecorder()
	handler.ServeHTTP(out, req)
	if out.Code != 403 {
		t.Fatalf("non-loopback host: %d", out.Code)
	}
}
