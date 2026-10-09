//go:build nknsdk

package nknclient

import (
	"context"
	"errors"
	nkn "github.com/nknorg/nkn-sdk-go"
	"testing"
	"time"
)

func TestInitialDeliveryRequiresEncryptedSelfNonce(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ch := make(chan *nkn.Message, 4)
	ch <- &nkn.Message{Src: "other", Encrypted: true, Data: []byte("nonce")}
	ch <- &nkn.Message{Src: "self", Encrypted: false, Data: []byte("nonce")}
	ch <- &nkn.Message{Src: "self", Encrypted: true, Data: []byte("old")}
	ch <- &nkn.Message{Src: "__1__.self", Encrypted: true, Data: []byte("nonce")}
	if err := waitDelivery(ctx, "self", []byte("nonce"), ch, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
}

func TestInitialDeliveryCancelsBlockedSendAndRejectsClosedReceive(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	blocked, started, finished := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		finished <- waitDelivery(ctx, "self", []byte("nonce"), nil, func() error { close(started); <-blocked; return nil })
	}()
	<-started
	cancel()
	select {
	case err := <-finished:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked SDK send defeated startup cancellation")
	}
	close(blocked)
	ch := make(chan *nkn.Message)
	close(ch)
	if err := waitDelivery(context.Background(), "self", []byte("nonce"), ch, func() error { return nil }); err == nil {
		t.Fatal("closed channel granted readiness")
	}
}
