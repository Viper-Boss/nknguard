package discovery

import (
	"encoding/json"
	"errors"
	"github.com/Viper-Boss/nknguard/pkg/identity"
	"testing"
	"time"
)

func TestRenewalPreservesSignedRecordAndRejectsStaleOrTamperedFields(t *testing.T) {
	device, _ := identity.Generate()
	first := signed(t, device, "net", 1)
	next := signed(t, device, "net", 2)
	renewal := NewRenewal(next)
	applied, err := renewal.Apply(first, "net", time.Now())
	if err != nil || applied.Sequence != 2 {
		t.Fatalf("valid renewal rejected: %v", err)
	}
	full, _ := json.Marshal(next)
	compact, _ := json.Marshal(renewal)
	if len(compact) >= len(full) {
		t.Fatal("renewal did not reduce payload")
	}
	if _, err = renewal.Apply(next, "net", time.Now()); !errors.Is(err, ErrRecordSuperseded) {
		t.Fatal("replayed renewal accepted")
	}
	forged := renewal
	forged.ExpiresAt++
	if _, err = forged.Apply(first, "net", time.Now()); err == nil {
		t.Fatal("unsigned lifetime extension accepted")
	}
	poisoned := first
	poisoned.WireGuardPublicKey = "attacker="
	if _, err = renewal.Apply(poisoned, "net", time.Now()); !errors.Is(err, ErrRenewalBase) {
		t.Fatal("wrong base accepted")
	}
	if _, err = renewal.Apply(first, "net", time.Now().Add(MaxRecordTTL)); err == nil {
		t.Fatal("expired renewal accepted")
	}
}
