//go:build nknsdk

package usagestats

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	nkn "github.com/nknorg/nkn-sdk-go"

	"github.com/Viper-Boss/nknguard/pkg/nknclient"
)

// A zero-fee transaction shares each block's small free quota with others and
// occasionally waits a few blocks, or is dropped. A check-in counts only once
// the new expiry is visible on chain; otherwise it is retried later.
const (
	confirmPoll     = 20 * time.Second
	confirmAttempts = 15 // five minutes
)

type nknChain struct {
	wallet  *nkn.Wallet
	address string
}

// NewNKNChain returns the chain client for the statistics key derived from
// the device's NKN seed. It talks JSON-RPC to the seed nodes (configured,
// then the built-in China seed, then the official seeds) and needs no NKN
// session, so it works whether or not the device is connected.
func NewNKNChain(nknSeed []byte, seedRPC []string) (Chain, error) {
	account, err := nkn.NewAccount(DeriveSeed(nknSeed))
	if err != nil {
		return nil, fmt.Errorf("usage statistics key: %w", err)
	}
	wallet, err := nkn.NewWallet(account, &nkn.WalletConfig{
		SeedRPCServerAddr: nkn.NewStringArray(nknclient.SeedRPCList(seedRPC)...),
		RPCTimeout:        10000,
	})
	if err != nil {
		return nil, fmt.Errorf("usage statistics wallet: %w", err)
	}
	// With an empty identifier the subscriber name is the bare public key.
	return &nknChain{wallet: wallet, address: hex.EncodeToString(account.PubKey())}, nil
}

func (c *nknChain) Address() string { return c.address }

func (c *nknChain) Subscribe(ctx context.Context, topic string, blocks int) error {
	height, err := c.wallet.GetHeightContext(ctx)
	if err != nil {
		return fmt.Errorf("block height: %w", err)
	}
	if _, err := c.wallet.SubscribeContext(ctx, "", topic, blocks, "", nil); err != nil {
		return err
	}
	want := height + int32(blocks)
	for i := 0; i < confirmAttempts; i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(confirmPoll):
		}
		subscription, err := c.wallet.GetSubscriptionContext(ctx, topic, c.address)
		if err == nil && subscription != nil && subscription.ExpiresAt >= want {
			return nil
		}
	}
	return errors.New("submitted but not written to a block within 5 minutes")
}

func (c *nknChain) Unsubscribe(ctx context.Context, topic string) error {
	_, err := c.wallet.UnsubscribeContext(ctx, "", topic, nil)
	return err
}

func (c *nknChain) Count(ctx context.Context, topic string) (int, error) {
	return c.wallet.GetSubscribersCountContext(ctx, topic, nil)
}
