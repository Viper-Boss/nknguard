package app

import (
	"context"
	"errors"
	"github.com/Viper-Boss/nknguard/pkg/releaseupdate"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestPreparedUpdateRequiresVerifiedBytesAndRestoresWithoutNetwork(t *testing.T) {
	for _, valid := range []bool{true, false} {
		t.Run(map[bool]string{true: "verified", false: "bad-signature"}[valid], func(t *testing.T) {
			d := &Daemon{}
			d.Config.Paths.StateDir = t.TempDir()
			var mu sync.Mutex
			u := newUpdatePrefetch(d, &mu, "fixture")
			u.fetch = func(ctx context.Context, url, path string, p func(int64, int64)) error {
				return os.WriteFile(path, []byte("fixture"), 0600)
			}
			u.stage = func(source, destination, current, kind, arch string) (releaseupdate.Asset, string, error) {
				if !valid {
					return releaseupdate.Asset{}, "", errors.New("bad signature")
				}
				if kind != "fixture" || arch != runtime.GOARCH {
					t.Error("wrong architecture")
				}
				_, err := os.ReadFile(source)
				return releaseupdate.Asset{}, "v9.0.0", err
			}
			r := releaseupdate.Result{Available: true, Latest: "v9.0.0", BundleURL: "https://github.com/example", Asset: &releaseupdate.Asset{}}
			if !u.start(context.Background(), &r) {
				t.Fatal("could not start")
			}
			deadline := time.Now().Add(3 * time.Second)
			for {
				mu.Lock()
				active := u.active
				mu.Unlock()
				if !active {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("download stuck")
				}
				time.Sleep(time.Millisecond)
			}
			mu.Lock()
			ready := u.download.State == "ready"
			mu.Unlock()
			if ready != valid {
				t.Fatal("unverified download offered for installation")
			}
			if valid {
				copy := newUpdatePrefetch(d, &mu, "fixture")
				copy.stage = u.stage
				copy.restore()
				if copy.download.State != "ready" {
					t.Fatal("ready package not restored")
				}
				_ = os.Remove(filepath.Join(copy.readyDir, "incoming.zip"))
				copy.restore()
				if _, err := os.Stat(filepath.Join(d.Config.Paths.StateDir, "updates", "ready.json")); !os.IsNotExist(err) {
					t.Fatal("missing package trusted")
				}
			}
		})
	}
}

func TestLivePrefetchSignedRelease(t *testing.T) {
	if os.Getenv("NKG_LIVE_UPDATE_TEST") != "1" {
		t.Skip("explicit live download check only")
	}
	d := &Daemon{}
	d.Config.Paths.StateDir = t.TempDir()
	var mu sync.Mutex
	u := newUpdatePrefetch(d, &mu, "fnos")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	u.prepare(ctx, nil)
	if u.download.State != "ready" {
		t.Fatalf("live download not verified: %+v", u.download)
	}
	t.Logf("Signed fnOS %s update downloaded and verified: %s", runtime.GOARCH, u.download.Version)
}
