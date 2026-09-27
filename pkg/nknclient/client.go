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
	"context"
	"fmt"
	"strings"
	"time"

	nkn "github.com/nknorg/nkn-sdk-go"
)

// Identifier is the NKN address prefix for NKNGuard clients, so an address in
// a log is recognisably ours: nknguard.<public key hex>.
const Identifier = "nknguard"

// SubClients is how many parallel NKN node connections the MultiClient keeps.
// Two is NasSimHub's production value: enough that one flaky node does not
// stall signalling, few enough for an ARM NAS.
const SubClients = 2

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
	account, err := nkn.NewAccount(options.Seed)
	if err != nil {
		return nil, fmt.Errorf("nknclient: account: %w", err)
	}
	config := &nkn.ClientConfig{SeedRPCServerAddr: nkn.NewStringArray(SeedRPCList(options.SeedRPC)...)}
	client, err := nkn.NewMultiClient(account, Identifier, SubClients, false, config)
	if err != nil {
		return nil, fmt.Errorf("nknclient: create: %w", err)
	}
	timer := time.NewTimer(ConnectTimeout)
	defer timer.Stop()
	select {
	case <-client.OnConnect.C:
		return client, nil
	case <-timer.C:
		_ = client.Close()
		return nil, fmt.Errorf("nknclient: connect timed out after %s", ConnectTimeout)
	case <-ctx.Done():
		_ = client.Close()
		return nil, ctx.Err()
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
