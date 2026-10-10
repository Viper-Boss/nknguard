package mobile

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestRecoveryTimeoutPublishesStoppedStatusBeforeCancel(t *testing.T) {
	var output bytes.Buffer
	a := &Agent{StateDir: t.TempDir(), out: json.NewEncoder(&output)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &session{agent: a, phase: PhaseWaiting, started: time.Now(), done: make(chan struct{}), cancel: cancel}
	a.session = s
	s.stopAfterRecoveryTimeout()
	if ctx.Err() == nil {
		t.Fatal("timeout did not cancel the session")
	}
	var event struct {
		Event string `json:"event"`
		Data  Status `json:"data"`
	}
	if err := json.Unmarshal(output.Bytes(), &event); err != nil {
		t.Fatal(err)
	}
	if event.Event != "status" || event.Data.Connected || event.Data.Phase != PhaseError || event.Data.ConnectionPhase != "disconnected" || event.Data.RecoveryRemaining != 0 {
		t.Fatalf("stopped status missing: %+v", event)
	}
}
