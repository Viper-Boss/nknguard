package releaseupdate

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDownloadStagingBoundsAndCleanup(t *testing.T) {
	for _, tc := range []struct {
		name   string
		length int64
		body   string
		ok     bool
	}{{"complete", 7, "archive", true}, {"incomplete", 9, "archive", false}, {"oversized", MaxPackageSize + 1, "archive", false}, {"empty", 0, "", false}} {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "incoming.zip")
			c := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 200, ContentLength: tc.length, Body: io.NopCloser(strings.NewReader(tc.body))}, nil
			})}
			err := DownloadBundle(context.Background(), c, ReleaseURL+"/download/v1.0.0/package.zip", p, nil)
			if (err == nil) != tc.ok {
				t.Fatal(err)
			}
			if _, err := os.Stat(p + ".part"); !os.IsNotExist(err) {
				t.Fatal("partial archive left behind")
			}
			if !tc.ok {
				if _, err := os.Stat(p); !os.IsNotExist(err) {
					t.Fatal("bad archive marked ready")
				}
			}
		})
	}
}
