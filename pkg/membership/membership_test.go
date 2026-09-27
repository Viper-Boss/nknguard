package membership

import "testing"

func TestProofBindsDeviceAndSecret(t *testing.T) {
	network, _ := NewNetworkID()
	secret, _ := NewJoinSecret()
	key, err := Derive(network, secret)
	if err != nil {
		t.Fatal(err)
	}
	proof := key.Proof("nkg_a", []byte("root-a"))
	if err := key.Verify("nkg_a", []byte("root-a"), proof); err != nil {
		t.Fatalf("own proof rejected: %v", err)
	}
	if err := key.Verify("nkg_b", []byte("root-a"), proof); err != ErrBadProof {
		t.Fatal("proof moved to another device id")
	}
	if err := key.Verify("nkg_a", []byte("root-b"), proof); err != ErrBadProof {
		t.Fatal("proof moved to another root key")
	}
	otherSecret, _ := NewJoinSecret()
	outsider, _ := Derive(network, otherSecret)
	if err := outsider.Verify("nkg_a", []byte("root-a"), proof); err != ErrBadProof {
		t.Fatal("proof verified under a different join secret")
	}
	if err := key.Verify("nkg_a", []byte("root-a"), nil); err != ErrNoProof {
		t.Fatal("missing proof accepted")
	}
}

func TestRendezvousDependsOnSecret(t *testing.T) {
	network, _ := NewNetworkID()
	s1, _ := NewJoinSecret()
	s2, _ := NewJoinSecret()
	k1, _ := Derive(network, s1)
	k1b, _ := Derive(network, s1)
	k2, _ := Derive(network, s2)
	if k1.Rendezvous() != k1b.Rendezvous() {
		t.Fatal("rendezvous not deterministic")
	}
	if k1.Rendezvous() == k2.Rendezvous() {
		t.Fatal("rendezvous does not depend on the secret — network id alone would enumerate members")
	}
}

func TestValidation(t *testing.T) {
	network, _ := NewNetworkID()
	secret, _ := NewJoinSecret()
	if !ValidNetworkID(network) || !ValidJoinSecret(secret) {
		t.Fatal("generated values do not validate")
	}
	if _, err := Derive("home", secret); err != ErrBadNetworkID {
		t.Fatal("guessable network id accepted")
	}
	if _, err := Derive(network, "hunter2"); err != ErrBadJoinSecret {
		t.Fatal("weak join secret accepted")
	}
}
