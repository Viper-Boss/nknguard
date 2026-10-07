package mobile

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

func (a *Agent) persistSecrets(ctx context.Context, values map[string][]byte) error {
	a.secretMu.Lock()
	a.secretSequence++
	sequence := a.secretSequence
	if a.secretWait == nil {
		a.secretWait = make(map[uint64]chan error)
	}
	ack := make(chan error, 1)
	a.secretWait[sequence] = ack
	a.secretMu.Unlock()
	defer func() { a.secretMu.Lock(); delete(a.secretWait, sequence); a.secretMu.Unlock() }()
	a.emit("secrets", map[string]any{"sequence": sequence, "values": Encode(values)})
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	select {
	case err := <-ack:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return errors.New("device keys were not confirmed saved; retry initialization or pairing")
	}
}

func (a *Agent) ackSecrets(raw json.RawMessage) {
	var ack struct {
		Sequence uint64 `json:"sequence"`
		Saved    bool   `json:"saved"`
	}
	if json.Unmarshal(raw, &ack) != nil {
		return
	}
	a.secretMu.Lock()
	wait := a.secretWait[ack.Sequence]
	a.secretMu.Unlock()
	if wait == nil {
		return
	}
	var err error
	if !ack.Saved {
		err = errors.New("cannot save device keys; check device storage and retry")
	}
	select {
	case wait <- err:
	default:
	}
}
