//go:build windows && nknsdk

package nknclient

import (
	"context"
	"crypto/rand"
	"os"
	"testing"
	"time"
)

func TestLiveWindowsNKNDelivery(t *testing.T) {
	if os.Getenv("NKG_LIVE_WINDOWS") != "1" {
		t.Skip("opt in live network probe")
	}
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
		started := time.Now()
		client, err := Open(ctx, Options{Seed: seed})
		cancel()
		if err != nil {
			t.Errorf("connect %d failed after %s: %v", i+1, time.Since(started), err)
			continue
		}
		t.Logf("connect %d encrypted self-delivery verified in %s", i+1, time.Since(started))
		client.Close()
	}
}
