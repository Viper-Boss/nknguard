package releaseupdate

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestCatalogueSignatureAndAssetSafety(t *testing.T) {
	pub, private, _ := ed25519.GenerateKey(rand.Reader)
	for _, name := range []string{"nknguard-linux-arm64", "../nknguard", "..", "dir/nknguard", "nknguard\\bad", "nknguard?bad", "nknguard%2fbad"} {
		m := Manifest{Version: "v0.2.15-preview.1", Assets: []Asset{{Name: name, Kind: "linux", Arch: "arm64", Size: 1, SHA256: strings.Repeat("a", 64)}}}
		raw, _ := json.Marshal(m)
		sig := ed25519.Sign(private, raw)
		_, err := verifyManifest(raw, sig, pub)
		if (err == nil) != (name == "nknguard-linux-arm64") {
			t.Fatalf("unexpected acceptance for %q: %v", name, err)
		}
		if name == "nknguard-linux-arm64" {
			raw[len(raw)-2] ^= 1
			if _, err := verifyManifest(raw, sig, pub); err == nil {
				t.Fatal("accepted tampered signed catalogue")
			}
		}
	}
}

func TestPreviewVersionOrdering(t *testing.T) {
	for _, tc := range []struct {
		latest, current string
		newer           bool
	}{
		{"0.2.15-preview.2", "0.2.15-preview.1", true},
		{"v0.2.15-preview.10", "0.2.15-preview.2", true},
		{"0.2.15", "0.2.15-preview.1", true},
		{"0.2.15-preview.2", "0.2.15", false},
		{"0.2.14", "0.2.15-preview.1", false},
		{"0.2.15-preview.1", "v0.2.15-preview.1", false},
	} {
		if got := Newer(tc.latest, tc.current); got != tc.newer {
			t.Errorf("%s vs %s: %v", tc.latest, tc.current, got)
		}
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestFetchBoundsAndOrigin(t *testing.T) {
	requests := 0
	c := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		requests++
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("oversized")), Header: http.Header{}}, nil
	})}
	for _, location := range []string{"http://github.com/Viper-Boss/nknguard/releases/a", "https://github.com/other/repo/releases/a", "https://evil.example/a", "https://github.com:443/Viper-Boss/nknguard/releases/a", "https://api.github.com/repos/Viper-Boss/nknguard/releases-other/assets/1"} {
		if _, err := Fetch(context.Background(), c, location, 4); err == nil {
			t.Fatalf("accepted %s", location)
		}
	}
	if requests != 0 {
		t.Fatal("contacted untrusted endpoint")
	}
	if _, err := Fetch(context.Background(), c, ReleaseURL+"/download/v0.2.15/release.json", 4); err == nil {
		t.Fatal("unbounded response accepted")
	}
}

func TestPublicAssetAPIDownload(t *testing.T) {
	c := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("Accept") != "application/octet-stream" {
			t.Fatal("asset API must request bytes rather than JSON metadata")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("signature")), Header: http.Header{}}, nil
	})}
	raw, err := Fetch(context.Background(), c, "https://api.github.com/repos/"+Repository+"/releases/assets/123", 64)
	if err != nil || string(raw) != "signature" {
		t.Fatalf("asset API download failed: %q %v", raw, err)
	}
}
