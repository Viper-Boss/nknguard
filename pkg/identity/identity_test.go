package identity

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestDeviceIDIsStableAndWellFormed(t *testing.T) {
	device, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	again, err := FromSeed(device.Seed())
	if err != nil {
		t.Fatal(err)
	}
	if device.DeviceID() != again.DeviceID() {
		t.Fatalf("device id changed across reload: %s vs %s", device.DeviceID(), again.DeviceID())
	}
	if !ValidDeviceID(device.DeviceID()) {
		t.Fatalf("generated id %q does not validate", device.DeviceID())
	}
	if ValidDeviceID("nkg_short") || ValidDeviceID("xyz_aaaaaaaaaaaaaaaa") {
		t.Fatal("malformed ids validated")
	}
}

func TestKeyBindingVerifiesAndRejectsTampering(t *testing.T) {
	device, _ := Generate()
	binding, err := device.NewKeyBinding(1, time.Hour, []byte("nknpub"), "nkn.addr", "wgpub=")
	if err != nil {
		t.Fatal(err)
	}
	if err := binding.Verify(time.Now()); err != nil {
		t.Fatalf("fresh binding rejected: %v", err)
	}

	tampered := binding
	tampered.WireGuardPublicKey = "attacker="
	if err := tampered.Verify(time.Now()); err != ErrBadSignature {
		t.Fatalf("tampered wg key accepted: %v", err)
	}

	other, _ := Generate()
	stolen := binding
	stolen.RootPublicKey = other.PublicKey()
	if err := stolen.Verify(time.Now()); err != ErrBindingMismatch {
		t.Fatalf("binding with swapped root key: %v", err)
	}

	if err := binding.Verify(time.Now().Add(2 * time.Hour)); err != ErrBindingExpired {
		t.Fatalf("expired binding: %v", err)
	}
}

func TestBindingSequenceOnlyMovesForward(t *testing.T) {
	device, _ := Generate()
	first, _ := device.NewKeyBinding(5, time.Hour, nil, "", "a=")
	second, _ := device.NewKeyBinding(6, time.Hour, nil, "", "b=")
	if !second.Supersedes(first) {
		t.Fatal("newer binding did not supersede")
	}
	if first.Supersedes(second) {
		t.Fatal("older binding superseded a newer one — that is a key downgrade")
	}
}

func TestKeystoreRootIsIdempotentAndPrivate(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keystore")
	store := NewKeystore(dir)
	first, err := store.LoadOrCreateRoot()
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.LoadOrCreateRoot()
	if err != nil {
		t.Fatal(err)
	}
	if first.DeviceID() != second.DeviceID() {
		t.Fatal("root identity regenerated on second load")
	}
	if runtime.GOOS == "windows" {
		return
	}
	info, err := os.Stat(filepath.Join(dir, "root.key"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != KeystoreFileMode {
		t.Fatalf("root key mode %04o, want %04o", info.Mode().Perm(), KeystoreFileMode)
	}
}

func TestKeystoreRefusesWorldReadableSecret(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits are not meaningful on windows")
	}
	dir := t.TempDir()
	store := NewKeystore(dir)
	if err := store.WriteSecret("x.key", []byte("secret")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, "x.key"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReadSecret("x.key"); err == nil {
		t.Fatal("world-readable secret was read without complaint")
	}
}
