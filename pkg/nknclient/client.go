//go:build nknsdk

// Package nknclient opens the one NKN MultiClient a node uses for signalling,
// rendezvous and relay.
//
// Every NKN capability here comes from github.com/nknorg/nkn-sdk-go — this
// package only chooses the options. The calls mirror the ones NasSimHub
// already runs in production (internal/httpapi/homesim_forward_nkn.go and
// cmd/nknpeer), so the adapter is built on API usage known to compile against
// nkn-sdk-go v1.4.8.
package nknclient

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"strings"
	"time"

	nkn "github.com/nknorg/nkn-sdk-go"
)

// Identifier is the NKN address prefix for NKNGuard clients, so an address in
// a log is recognisably ours: nknguard.<public key hex>.
const Identifier = "nknguard"

// SubClients is how many parallel NKN node connections the MultiClient keeps.
// Each sub-client identifier maps to a different position in the NKN ring.
// Recreating only the same two identifiers kept retrying the same unreachable
// nodes on mobile networks. Keep four paths on both ends; IDs 0 and 1 remain
// compatible with older peers, and the public base address stays unchanged.
const SubClients = 4

// ConnectTimeout bounds the initial connection to the NKN network.
const ConnectTimeout = 30 * time.Second

// SeedName is the keystore entry holding the NKN account seed. It is a
// separate key from the device root key on purpose (spec §7): the NKN address
// can be rotated without changing who the device is.
const SeedName = "nkn.seed"

// Options configures the client.
type Options struct {
	Seed []byte
	// SeedRPC lists extra NKN seed RPC servers (e.g. a self-hosted node),
	// tried before the built-in China and official seeds; see SeedRPCList.
	SeedRPC []string
}

// Open connects and waits for the first node connection.
func Open(ctx context.Context, options Options) (*nkn.MultiClient, error) {
	ctx, cancel := context.WithTimeout(ctx, ConnectTimeout)
	defer cancel()
	account, err := nkn.NewAccount(options.Seed)
	if err != nil {
		return nil, fmt.Errorf("nknclient: account: %w", err)
	}
	config := &nkn.ClientConfig{SeedRPCServerAddr: nkn.NewStringArray(SeedRPCList(options.SeedRPC)...),
		RPCTimeout: 5000, RPCConcurrency: 3, WsHandshakeTimeout: 6000,
		ConnectRetries: 1, MinReconnectInterval: 1000, MaxReconnectInterval: 8000}
	// SDK construction itself connects to nodes; include that in the bound.
	timer := time.NewTimer(ConnectTimeout)
	defer timer.Stop()
	type result struct {
		client *nkn.MultiClient
		err    error
	}
	created := make(chan result, 1)
	go func() {
		c, e := nkn.NewMultiClient(account, Identifier, SubClients, false, config)
		created <- result{c, e}
	}()
	var client *nkn.MultiClient
	lateClose := func() {
		go func() {
			if out := <-created; out.client != nil {
				_ = out.client.Close()
			}
		}()
	}
	select {
	case out := <-created:
		if out.err != nil {
			return nil, fmt.Errorf("nknclient: create: %w", out.err)
		}
		client = out.client
	case <-timer.C:
		lateClose()
		return nil, fmt.Errorf("nknclient: connect timed out after %s", ConnectTimeout)
	case <-ctx.Done():
		lateClose()
		return nil, ctx.Err()
	}
	select {
	case <-client.OnConnect.C:
		// Registration alone does not prove NKN can deliver a message.
		if err := checkDelivery(ctx, client); err != nil {
			_ = client.Close()
			return nil, fmt.Errorf("nknclient: initial delivery check: %w", err)
		}
		return client, nil
	case <-timer.C:
		_ = client.Close()
		return nil, fmt.Errorf("nknclient: connect timed out after %s", ConnectTimeout)
	case <-ctx.Done():
		_ = client.Close()
		return nil, ctx.Err()
	}
}

func checkDelivery(ctx context.Context, client *nkn.MultiClient) error {
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	payload := append([]byte("NKNGuard-bootstrap-v1:"), nonce...)
	return waitDelivery(ctx, NormaliseAddress(client.Address()), payload, client.OnMessage.C, func() error {
		_, err := client.Send(nkn.NewStringArray(client.Address()), payload, &nkn.MessageConfig{NoReply: true, MaxHoldingSeconds: 0})
		return err
	})
}

// Construction has no signalling consumer yet. Only an encrypted, fresh
// self-message can prove delivery; an unrelated buffered message cannot.
func waitDelivery(ctx context.Context, self string, payload []byte, messages <-chan *nkn.Message, send func() error) error {
	sent := make(chan error, 1)
	go func() { sent <- send() }()
	select {
	case err := <-sent:
		if err != nil {
			return fmt.Errorf("send: %w", err)
		}
	case <-ctx.Done():
		return ctx.Err()
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case message, ok := <-messages:
			if !ok {
				return fmt.Errorf("receive channel closed")
			}
			if message != nil && message.Encrypted && NormaliseAddress(message.Src) == self && bytes.Equal(message.Data, payload) {
				return nil
			}
		}
	}
}

// NormaliseAddress strips a MultiClient sub-client prefix ("__0__.") so the
// same peer is recognised whichever of its sub-clients a message came from.
func NormaliseAddress(address string) string {
	if strings.HasPrefix(address, "__") {
		if index := strings.Index(address[2:], "__."); index >= 0 {
			return address[2+index+3:]
		}
	}
	return address
}
