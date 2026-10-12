//go:build nknsdk

package nknsignal

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	random "math/rand/v2"
	"sync"
	"time"

	"github.com/Viper-Boss/nknguard/pkg/nknclient"
	"github.com/Viper-Boss/nknguard/pkg/rendezvous/nkntopic"
	nkn "github.com/nknorg/nkn-sdk-go"
)

const BootstrapTopic = "nknguard.dht.bootstrap.v1"

var bootstrapPrefix = []byte("NKNGuard-DHT-bootstrap-v1:")

type bootstrapBackend interface {
	BootstrapServer() bool
	BootstrapNeighborCount() int
	BootstrapProof(string, string) ([]byte, error)
	ConnectBootstrap(context.Context, []byte, string, string) error
	DiscoveryStatus() (int, int)
}
type bootstrapMessage struct {
	Nonce string `json:"nonce"`
	Sent  int64  `json:"sent"`
	Proof []byte `json:"proof,omitempty"`
}
type bootstrapInbound struct {
	source  string
	message bootstrapMessage
}
type bootstrapPending struct {
	nonce   string
	expires time.Time
}
type bootstrapState struct {
	mu        sync.Mutex
	inbox     chan bootstrapInbound
	pending   map[string]bootstrapPending
	replied   map[string]time.Time
	window    time.Time
	responses int
}

// StartDHTBootstrap uses a separate public topic. Mobile clients query only;
// servers renew at most twice daily. All probe messages have zero offline holding.
func (t *Transport) StartDHTBootstrap(ctx context.Context, backend any, seedRPC []string, logger *slog.Logger) {
	b, ok := backend.(bootstrapBackend)
	if !ok {
		return
	}
	if logger == nil {
		logger = slog.Default()
	}
	s := &bootstrapState{inbox: make(chan bootstrapInbound, 32), pending: map[string]bootstrapPending{}, replied: map[string]time.Time{}}
	t.mu.Lock()
	if t.bootstrap != nil {
		t.mu.Unlock()
		return
	}
	t.bootstrap = s
	t.mu.Unlock()
	go func() {
		source := nkntopic.New(t.client, BootstrapTopic, nknclient.SeedRPCList(seedRPC))
		// Expiry removes offline servers; shutdown does not create unsubscribe transactions.
		started := time.Now()
		timer := time.NewTimer(time.Duration(random.IntN(4000)) * time.Millisecond)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.done:
				return
			case <-timer.C:
				if b.BootstrapServer() {
					if err := source.Announce(ctx); err != nil {
						logger.Warn("DHT bootstrap subscription failed", "component", "dht-bootstrap", "error", err)
					}
				}
				connected := b.BootstrapNeighborCount()
				if connected < 4 {
					addresses, err := source.SampleAddresses(ctx, 64)
					if err != nil {
						logger.Warn("DHT bootstrap candidates unavailable", "component", "dht-bootstrap", "error", err)
					}
					random.Shuffle(len(addresses), func(i, j int) { addresses[i], addresses[j] = addresses[j], addresses[i] })
					count := 0
					for _, address := range addresses {
						address = nknclient.NormaliseAddress(address)
						if address == t.LocalAddress() {
							continue
						}
						if count >= 3 {
							break
						}
						count++
						var nonce [16]byte
						if _, err := rand.Read(nonce[:]); err != nil {
							continue
						}
						now := time.Now()
						s.mu.Lock()
						for a, p := range s.pending {
							if now.After(p.expires) {
								delete(s.pending, a)
							}
						}
						s.pending[address] = bootstrapPending{hex.EncodeToString(nonce[:]), now.Add(45 * time.Second)}
						s.mu.Unlock()
						_ = t.sendBootstrap(address, bootstrapMessage{Nonce: hex.EncodeToString(nonce[:]), Sent: now.Unix()})
					}
				}
				interval := 5 * time.Minute
				if connected < 2 && time.Since(started) < 5*time.Minute {
					interval = 45 * time.Second
				}
				timer.Reset(interval + time.Duration(random.IntN(15000))*time.Millisecond)
			case inbound := <-s.inbox:
				m := inbound.message
				now := time.Now()
				if len(m.Proof) == 0 {
					if !b.BootstrapServer() || !s.allowReply(inbound.source, now) {
						continue
					}
					proof, err := b.BootstrapProof(t.LocalAddress(), m.Nonce)
					if err != nil {
						continue
					}
					_ = t.sendBootstrap(inbound.source, bootstrapMessage{Nonce: m.Nonce, Sent: now.Unix(), Proof: proof})
				} else {
					s.mu.Lock()
					p, ok := s.pending[inbound.source]
					if ok && p.nonce == m.Nonce && now.Before(p.expires) {
						delete(s.pending, inbound.source)
					} else {
						ok = false
					}
					s.mu.Unlock()
					if !ok {
						continue
					}
					if err := b.ConnectBootstrap(ctx, m.Proof, inbound.source, m.Nonce); err != nil {
						logger.Debug("DHT bootstrap rejected", "component", "dht-bootstrap", "error", err)
					}
				}
			}
		}
	}()
}

func (s *bootstrapState) allowReply(source string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if now.Sub(s.window) >= time.Minute {
		s.window = now
		s.responses = 0
		for a, at := range s.replied {
			if now.Sub(at) >= time.Minute {
				delete(s.replied, a)
			}
		}
	}
	if s.responses >= 8 || len(s.replied) >= 128 || (!s.replied[source].IsZero() && now.Sub(s.replied[source]) < time.Minute) {
		return false
	}
	s.responses++
	s.replied[source] = now
	return true
}

func (t *Transport) sendBootstrap(address string, m bootstrapMessage) error {
	raw, err := json.Marshal(m)
	if err != nil {
		return err
	}
	_, err = t.client.Send(nkn.NewStringArray(address), append(bytes.Clone(bootstrapPrefix), raw...), &nkn.MessageConfig{NoReply: true, MaxHoldingSeconds: 0})
	return err
}

func (t *Transport) acceptBootstrap(source string, raw []byte) bool {
	if !bytes.HasPrefix(raw, bootstrapPrefix) {
		return false
	}
	t.mu.RLock()
	s := t.bootstrap
	t.mu.RUnlock()
	if s == nil || len(raw) > 12000 {
		return true
	}
	var m bootstrapMessage
	if json.Unmarshal(raw[len(bootstrapPrefix):], &m) != nil || len(m.Nonce) != 32 {
		return true
	}
	if _, err := hex.DecodeString(m.Nonce); err != nil {
		return true
	}
	now := time.Now().Unix()
	if m.Sent < now-45 || m.Sent > now+10 {
		return true
	}
	select {
	case s.inbox <- bootstrapInbound{source, m}:
	default:
	}
	return true
}
