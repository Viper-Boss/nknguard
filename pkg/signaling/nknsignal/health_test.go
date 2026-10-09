//go:build nknsdk

package nknsignal

import (
	"bytes"
	"testing"
	"time"
)

func TestHealthRejectsSpoofReplayAndExpiredProbe(t *testing.T) {
	var h healthState
	h.init("self")
	now := time.Now()
	packet := h.begin(bytes.Repeat([]byte{1}, 32), now)
	if h.accept("another-device", packet, now.Add(time.Second)) {
		t.Fatal("foreign source granted connectivity")
	}
	wrong := bytes.Clone(packet)
	wrong[len(wrong)-1] ^= 1
	if h.accept("self", wrong, now.Add(time.Second)) {
		t.Fatal("wrong nonce granted connectivity")
	}
	if !h.accept("self", packet, now.Add(time.Second)) {
		t.Fatal("valid self-message rejected")
	}
	if h.accept("self", packet, now.Add(2*time.Second)) {
		t.Fatal("replayed probe accepted")
	}
	if h.status.State != "connected" || h.status.LatencyMS != 1000 {
		t.Fatalf("status: %+v", h.status)
	}
	packet = h.begin(bytes.Repeat([]byte{2}, 32), now.Add(30*time.Second))
	if h.accept("self", packet, now.Add(30*time.Second+healthTimeout+time.Millisecond)) {
		t.Fatal("expired probe accepted")
	}
	h.failed("reconnecting", now.Add(43*time.Second))
	if h.status.State != "reconnecting" || h.status.LastSuccess.IsZero() {
		t.Fatalf("lost failure or last success: %+v", h.status)
	}
	packet = h.begin(bytes.Repeat([]byte{3}, 32), now.Add(60*time.Second))
	if !h.accept("self", packet, now.Add(61*time.Second)) {
		t.Fatal("recovery probe rejected")
	}
}

func TestConnectionStatusExpiresAndCloses(t *testing.T) {
	transport := &Transport{done: make(chan struct{})}
	transport.health.init("self")
	transport.health.status.State = "connected"
	transport.health.status.LastSuccess = time.Now().Add(-healthInterval - healthTimeout - time.Second)
	if transport.ConnectionStatus().State != "reconnecting" {
		t.Fatal("stale success shown as connected")
	}
	close(transport.done)
	if transport.ConnectionStatus().State != "closed" {
		t.Fatal("closed transport shown as connected")
	}
}

func TestFailedChecksReconnectOnlyAfterTwoRoundsAndResetOnRecovery(t *testing.T) {
	var h healthState
	h.init("self")
	now := time.Now()
	h.failed("reconnecting", now)
	if h.reconnectDue() {
		t.Fatal("one delayed probe triggered reconnect")
	}
	h.failed("reconnecting", now.Add(30*time.Second))
	if !h.reconnectDue() || h.reconnectDue() {
		t.Fatal("failed rounds did not grant exactly one reconnect")
	}
	h.failed("reconnecting", now)
	packet := h.begin(bytes.Repeat([]byte{1}, 32), now)
	if !h.accept("self", packet, now.Add(time.Second)) {
		t.Fatal("recovery failed")
	}
	h.failed("reconnecting", now.Add(30*time.Second))
	if h.reconnectDue() {
		t.Fatal("recovery did not reset failure history")
	}
}
