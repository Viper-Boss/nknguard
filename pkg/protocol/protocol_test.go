package protocol

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Viper-Boss/nknguard/pkg/identity"
)

func mustDevice(t *testing.T) *identity.DeviceIdentity {
	t.Helper()
	device, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return device
}

func TestSealVerifyRoundTrip(t *testing.T) {
	alice, bob := mustDevice(t), mustDevice(t)
	envelope, err := Seal(alice, "net1", bob.DeviceID(), TypeHello, Hello{Versions: LocalVersionRange()})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := envelope.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Unmarshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	acceptor := &Acceptor{NetworkID: "net1", LocalDeviceID: bob.DeviceID(), Replay: NewReplayCache(0, 0)}
	if err := acceptor.Verify(decoded); err != nil {
		t.Fatalf("valid envelope rejected: %v", err)
	}
	var hello Hello
	if err := decoded.DecodePayload(&hello); err != nil || hello.Versions.Max != Version {
		t.Fatalf("payload did not survive: %+v %v", hello, err)
	}
}

func TestVerifyRejections(t *testing.T) {
	alice, bob, mallory := mustDevice(t), mustDevice(t), mustDevice(t)
	fresh := func() Envelope {
		envelope, err := Seal(alice, "net1", bob.DeviceID(), TypeKeepalive, nil)
		if err != nil {
			t.Fatal(err)
		}
		return envelope
	}
	cases := []struct {
		name   string
		mutate func(*Envelope)
		accept Acceptor
		want   error
	}{
		{"tampered type", func(e *Envelope) { e.Type = TypeDisconnect }, Acceptor{NetworkID: "net1"}, ErrBadSignature},
		{"claimed another device", func(e *Envelope) { e.FromDeviceID = mallory.DeviceID() }, Acceptor{NetworkID: "net1"}, ErrBadSignature},
		{"wrong network", func(*Envelope) {}, Acceptor{NetworkID: "net2"}, ErrWrongNetwork},
		{"not for us", func(*Envelope) {}, Acceptor{NetworkID: "net1", LocalDeviceID: mallory.DeviceID()}, ErrNotAddressed},
		{"future version", func(e *Envelope) { e.ProtocolVersion = Version + 1 }, Acceptor{NetworkID: "net1"}, ErrUnsupportedPV},
		{"from the past", func(*Envelope) {}, Acceptor{NetworkID: "net1", Now: func() time.Time { return time.Now().Add(10 * time.Minute) }}, ErrClockSkew},
		{"from the future", func(*Envelope) {}, Acceptor{NetworkID: "net1", Now: func() time.Time { return time.Now().Add(-time.Minute) }}, ErrClockSkew},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			envelope := fresh()
			tc.mutate(&envelope)
			accept := tc.accept
			if err := accept.Verify(envelope); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestReplayIsRejected(t *testing.T) {
	alice := mustDevice(t)
	envelope, _ := Seal(alice, "net1", "", TypeKeepalive, nil)
	acceptor := &Acceptor{NetworkID: "net1", Replay: NewReplayCache(0, 0)}
	if err := acceptor.Verify(envelope); err != nil {
		t.Fatal(err)
	}
	if err := acceptor.Verify(envelope); err != ErrReplay {
		t.Fatalf("replayed envelope: %v", err)
	}
}

func TestReplayCacheIsBounded(t *testing.T) {
	cache := NewReplayCache(time.Hour, 8)
	now := time.Now()
	for i := 0; i < 100; i++ {
		cache.Admit(strings.Repeat("x", i+1), now)
	}
	if cache.Len() != 8 {
		t.Fatalf("cache grew to %d, cap is 8", cache.Len())
	}
	cache = NewReplayCache(time.Second, 0)
	cache.Admit("a", now)
	if !cache.Admit("a", now.Add(2*time.Second)) {
		t.Fatal("expired id was not readmitted")
	}
}

func TestOversizeEnvelopeRefusedBothWays(t *testing.T) {
	alice := mustDevice(t)
	envelope, err := Seal(alice, "n", "", TypeHello, Hello{DeviceName: strings.Repeat("a", MaxEnvelopeBytes)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := envelope.Marshal(); err != ErrTooLarge {
		t.Fatalf("oversize marshal: %v", err)
	}
	if _, err := Unmarshal(make([]byte, MaxEnvelopeBytes+1)); err != ErrTooLarge {
		t.Fatalf("oversize unmarshal: %v", err)
	}
}

func TestNegotiate(t *testing.T) {
	if v, ok := Negotiate(VersionRange{1, 3}, VersionRange{2, 5}); !ok || v != 3 {
		t.Fatalf("overlap: %d %v", v, ok)
	}
	if _, ok := Negotiate(VersionRange{1, 1}, VersionRange{2, 2}); ok {
		t.Fatal("disjoint ranges negotiated")
	}
}
