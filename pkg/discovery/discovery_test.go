package discovery

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Viper-Boss/nknguard/pkg/identity"
)

func signed(t *testing.T, device *identity.DeviceIdentity, network string, sequence uint64) PeerRecord {
	t.Helper()
	record, err := Sign(device, PeerRecord{NetworkID: network, WireGuardPublicKey: "wg="}, sequence, DefaultRecordTTL, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func TestRecordVerification(t *testing.T) {
	device, _ := identity.Generate()
	record := signed(t, device, "net", 1)
	if err := record.Verify("net", time.Now()); err != nil {
		t.Fatalf("valid record: %v", err)
	}
	raw, _ := record.Marshal()
	decoded, _ := UnmarshalRecord(raw)
	if err := decoded.Verify("net", time.Now()); err != nil {
		t.Fatalf("record did not survive the wire: %v", err)
	}

	poisoned := record
	poisoned.WireGuardPublicKey = "attacker="
	if err := poisoned.Verify("net", time.Now()); err != ErrBadSignature {
		t.Fatalf("DHT-poisoned key accepted: %v", err)
	}
	if err := record.Verify("other", time.Now()); err != ErrWrongNetwork {
		t.Fatalf("cross-network record: %v", err)
	}
	if err := record.Verify("net", time.Now().Add(MaxRecordTTL+time.Second)); err != ErrRecordExpired {
		t.Fatalf("expired record: %v", err)
	}
	other, _ := identity.Generate()
	impostor := record
	impostor.DeviceID = other.DeviceID()
	if err := impostor.Verify("net", time.Now()); err != ErrDeviceMismatch {
		t.Fatalf("impostor device id: %v", err)
	}
}

func TestTTLIsClamped(t *testing.T) {
	device, _ := identity.Generate()
	now := time.Now()
	record, _ := Sign(device, PeerRecord{NetworkID: "n"}, 1, 24*time.Hour, now)
	if time.Unix(record.ExpiresAt, 0).Sub(now) > MaxRecordTTL+time.Second {
		t.Fatal("record TTL was not clamped — a record must not live forever")
	}
}

func TestVerifyRejectsInvalidTimeWindow(t *testing.T) {
	device, _ := identity.Generate()
	now := time.Unix(1_800_000_000, 0)
	record, err := Sign(device, PeerRecord{NetworkID: "n"}, 1, DefaultRecordTTL, now)
	if err != nil {
		t.Fatal(err)
	}
	mutated := record
	mutated.ExpiresAt = mutated.IssuedAt + int64(MaxRecordTTL.Seconds()) + 1
	mutated.Signature = device.Sign(mustSigningBytes(t, mutated))
	if err := mutated.Verify("n", now); !errors.Is(err, ErrInvalidRecordTime) {
		t.Fatalf("overlong record accepted: %v", err)
	}
	mutated = record
	mutated.IssuedAt = mutated.ExpiresAt + 1
	mutated.Signature = device.Sign(mustSigningBytes(t, mutated))
	if err := mutated.Verify("n", now); !errors.Is(err, ErrRecordExpired) {
		t.Fatalf("inverted times accepted: %v", err)
	}
}

func TestVerifyRejectsFarFutureIssueTime(t *testing.T) {
	device, _ := identity.Generate()
	now := time.Now()
	record, err := Sign(device, PeerRecord{NetworkID: "n"}, 1, DefaultRecordTTL, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err := record.Verify("n", now); !errors.Is(err, ErrInvalidRecordTime) {
		t.Fatalf("far-future record accepted: %v", err)
	}
}

func mustSigningBytes(t *testing.T, record PeerRecord) []byte {
	t.Helper()
	data, err := record.signingBytes()
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestCacheKeepsNewest(t *testing.T) {
	device, _ := identity.Generate()
	cache := NewCache(0)
	newer := signed(t, device, "n", 5)
	older := signed(t, device, "n", 4)
	if !cache.Put(newer) {
		t.Fatal("first put ignored")
	}
	if cache.Put(older) {
		t.Fatal("older record replaced a newer one")
	}
	if cache.Put(newer) {
		t.Fatal("identical republish reported as a change")
	}
}

func TestCachePutVerifiedRejectsForgedOrExpiredRecords(t *testing.T) {
	device, _ := identity.Generate()
	cache := NewCache(0)
	now := time.Now()
	record, _ := Sign(device, PeerRecord{NetworkID: "n"}, 1, DefaultRecordTTL, now)
	if err := cache.PutVerified(record, "n", now); err != nil {
		t.Fatalf("valid record rejected: %v", err)
	}
	bad := record
	bad.Name = "tampered"
	if err := cache.PutVerified(bad, "n", now); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("forgery accepted: %v", err)
	}
	if err := cache.PutVerified(record, "n", now.Add(MaxRecordTTL+time.Second)); !errors.Is(err, ErrRecordExpired) {
		t.Fatalf("expired record accepted: %v", err)
	}
}

func TestCacheIsBounded(t *testing.T) {
	cache := NewCache(2)
	for i := 0; i < 5; i++ {
		device, _ := identity.Generate()
		cache.Put(signed(t, device, "n", 1))
	}
	if cache.Len() != 2 {
		t.Fatalf("cache holds %d, limit 2", cache.Len())
	}
}

func TestMemoryPublishLookupWatch(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := NewMemory("n")
	updates, err := store.Watch(ctx, "n")
	if err != nil {
		t.Fatal(err)
	}
	device, _ := identity.Generate()
	record := signed(t, device, "n", 1)
	if err := store.Publish(ctx, record); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-updates:
		if got.DeviceID != device.DeviceID() {
			t.Fatal("watch delivered the wrong record")
		}
	case <-time.After(time.Second):
		t.Fatal("watch did not fire")
	}
	found, _ := store.Lookup(ctx, "n")
	if len(found) != 1 {
		t.Fatalf("lookup returned %d records", len(found))
	}
	bad := record
	bad.Name = "tampered"
	if err := store.Publish(ctx, bad); err == nil {
		t.Fatal("tampered record was stored")
	}
	cancel()
	select {
	case _, open := <-updates:
		if open {
			t.Fatal("unexpected record after cancel")
		}
	case <-time.After(time.Second):
		t.Fatal("watch channel not closed on cancel")
	}
}
