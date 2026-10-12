//go:build nknsdk

package nknsignal

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestPublicBootstrapRateAndExpiry(t *testing.T) {
	s := &bootstrapState{inbox: make(chan bootstrapInbound, 32), pending: map[string]bootstrapPending{}, replied: map[string]time.Time{}}
	now := time.Now()
	if !s.allowReply("first", now) || s.allowReply("first", now) {
		t.Fatal("per-source rate limit failed")
	}
	for i := 0; i < 7; i++ {
		if !s.allowReply(fmt.Sprint(i), now) {
			t.Fatal("early global limit")
		}
	}
	if s.allowReply("overflow", now) {
		t.Fatal("global rate limit failed")
	}
	if !s.allowReply("first", now.Add(time.Minute)) {
		t.Fatal("rate window did not recover")
	}
	transport := &Transport{bootstrap: s}
	for _, stamp := range []int64{now.Unix(), now.Add(-time.Hour).Unix(), now.Add(time.Hour).Unix()} {
		raw, _ := json.Marshal(bootstrapMessage{Nonce: strings.Repeat("a", 32), Sent: stamp})
		if !transport.acceptBootstrap("source", append(append([]byte(nil), bootstrapPrefix...), raw...)) {
			t.Fatal("bootstrap reached mesh dispatcher")
		}
	}
	if len(s.inbox) != 1 {
		t.Fatal("expired bootstrap message accepted")
	}
}
