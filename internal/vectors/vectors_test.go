// Package vectors pins the v1 wire format with fixed test vectors.
//
// testdata/v1.json is generated from fixed keys, nonces and timestamps by the
// same code the NAS, the Windows client and the Android core run. The test
// fails if any byte of it changes, so an accidental wire change cannot pass
// review silently, and a non-Go implementation can check itself against the
// file field by field. Regenerate deliberately with:
//
//	go test ./internal/vectors -update
package vectors

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Viper-Boss/nknguard/internal/app"
	"github.com/Viper-Boss/nknguard/pkg/discovery"
	"github.com/Viper-Boss/nknguard/pkg/identity"
	"github.com/Viper-Boss/nknguard/pkg/membership"
	"github.com/Viper-Boss/nknguard/pkg/mesh"
	"github.com/Viper-Boss/nknguard/pkg/nat"
	"github.com/Viper-Boss/nknguard/pkg/protocol"
)

var update = flag.Bool("update", false, "rewrite testdata/v1.json")

// Vectors is the file format. Byte strings are hex unless the field name
// says base64; *_json fields are the exact bytes as a string.
type Vectors struct {
	Note     string          `json:"note"`
	Identity []IdentityCase  `json:"identity"`
	PairCode []PairCodeCase  `json:"pair_code"`
	Invite   InviteCase      `json:"invite"`
	Envelope EnvelopeCase    `json:"envelope"`
	Member   MembershipCase  `json:"membership"`
	Record   RecordCase      `json:"peer_record"`
	Relay    []RelayCase     `json:"relay_frame"`
	Address  VirtualAddrCase `json:"virtual_ip"`
}

type IdentityCase struct {
	RootSeedHex      string `json:"root_seed_hex"`
	PublicKeyBase64  string `json:"public_key_base64"`
	DeviceID         string `json:"device_id"`
	PublicKeySHA256  string `json:"public_key_sha256_hex"`
	DeviceIDEncoding string `json:"device_id_rule"`
}

type PairCodeCase struct {
	Token      string `json:"token"`
	DeviceID   string `json:"device_id"`
	WGKey      string `json:"wireguard_public_key"`
	InputJSON  string `json:"input_json"`
	InputSHA   string `json:"input_sha256_hex"`
	FirstFour  uint32 `json:"first_four_bytes_be"`
	Code       string `json:"code"`
	CodeFormat string `json:"rule"`
}

type InviteCase struct {
	JSON string `json:"json"`
	URI  string `json:"uri"`
}

type EnvelopeCase struct {
	SenderSeedHex  string `json:"sender_seed_hex"`
	NonceHex       string `json:"nonce_hex"`
	TimestampMilli int64  `json:"timestamp_unix_milli"`
	PayloadJSON    string `json:"payload_json"`
	SigningJSON    string `json:"signing_json"`
	SignatureB64   string `json:"signature_base64"`
	WireJSON       string `json:"wire_json"`
}

type MembershipCase struct {
	NetworkID      string `json:"network_id"`
	JoinSecret     string `json:"join_secret"`
	DeviceID       string `json:"device_id"`
	RootPublicB64  string `json:"root_public_key_base64"`
	ProofBase64    string `json:"proof_base64"`
	RendezvousName string `json:"rendezvous_topic"`
}

type RecordCase struct {
	SignedAtUnix int64  `json:"signed_at_unix"`
	SigningJSON  string `json:"signing_json"`
	WireJSON     string `json:"wire_json"`
}

type RelayCase struct {
	DatagramHex string `json:"datagram_hex"`
	FrameHex    string `json:"frame_hex"`
}

type VirtualAddrCase struct {
	OverlayCIDR string `json:"overlay_cidr"`
	NetworkID   string `json:"network_id"`
	DeviceID    string `json:"device_id"`
	Address     string `json:"address"`
}

func seed(label string) []byte {
	sum := sha256.Sum256([]byte("nknguard test vector " + label))
	return sum[:]
}

func mustIdentity(t *testing.T, label string) *identity.DeviceIdentity {
	t.Helper()
	device, err := identity.FromSeed(seed(label))
	if err != nil {
		t.Fatal(err)
	}
	return device
}

func build(t *testing.T) Vectors {
	t.Helper()
	out := Vectors{Note: "NKNGuard protocol v1 test vectors; see internal/vectors/vectors_test.go and docs/PROTOCOL.md"}
	for _, label := range []string{"nas", "phone"} {
		device := mustIdentity(t, label)
		sum := sha256.Sum256(device.PublicKey())
		out.Identity = append(out.Identity, IdentityCase{
			RootSeedHex: hex.EncodeToString(seed(label)), PublicKeyBase64: base64.StdEncoding.EncodeToString(device.PublicKey()),
			DeviceID: device.DeviceID(), PublicKeySHA256: hex.EncodeToString(sum[:]),
			DeviceIDEncoding: "nkg_ + lowercase unpadded RFC 4648 base32 of sha256[:10]",
		})
	}
	nas, phone := mustIdentity(t, "nas"), mustIdentity(t, "phone")
	wgKey := base64.StdEncoding.EncodeToString(seed("wireguard"))
	for _, token := range []string{base64.RawURLEncoding.EncodeToString(seed("token")), "short-but-valid-for-the-code-only-000000000"} {
		input, _ := json.Marshal(struct{ Token, DeviceID, WGKey string }{token, phone.DeviceID(), wgKey})
		sum := sha256.Sum256(input)
		out.PairCode = append(out.PairCode, PairCodeCase{
			Token: token, DeviceID: phone.DeviceID(), WGKey: wgKey, InputJSON: string(input), InputSHA: hex.EncodeToString(sum[:]),
			FirstFour: binary.BigEndian.Uint32(sum[:4]), Code: app.PairCode(token, phone.DeviceID(), wgKey),
			CodeFormat: "%06d of first_four_bytes_be mod 1000000",
		})
	}

	networkID := "nkgnet_" + "aaaaaaaaaaaaaaaaaaaaaaaaaa"
	if !membership.ValidNetworkID(networkID) {
		t.Fatalf("vector network id %q is not valid", networkID)
	}
	invite := app.PairInvite{
		Version: 1, NetworkID: networkID, NASID: nas.DeviceID(), NASPublicKey: nas.PublicKey(),
		NASAddress: "nknguard." + hex.EncodeToString(seed("nkn")), Token: out.PairCode[0].Token,
		ExpiresAt: time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC),
	}
	inviteJSON, _ := json.Marshal(invite)
	uri, err := invite.URI()
	if err != nil {
		t.Fatal(err)
	}
	out.Invite = InviteCase{JSON: string(inviteJSON), URI: uri}

	nonce := seed("nonce")[:16]
	payload, _ := json.Marshal(protocol.PairRequest{Token: invite.Token, Name: "Pixel", NKNAddress: "nknguard." + hex.EncodeToString(seed("phone-nkn")), WireGuardPublicKey: wgKey})
	messageID := sha256.Sum256(nonce)
	envelope := protocol.Envelope{
		ProtocolVersion: 1, MessageID: base64.RawURLEncoding.EncodeToString(messageID[:12]), NetworkID: networkID,
		FromDeviceID: phone.DeviceID(), FromPublicKey: phone.PublicKey(), ToDeviceID: nas.DeviceID(),
		Type: protocol.TypePairRequest, Timestamp: 1790000000000, Nonce: nonce, Payload: payload,
	}
	signing, _ := json.Marshal(envelope)
	envelope.Signature = phone.Sign(signing)
	wire, err := envelope.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	out.Envelope = EnvelopeCase{
		SenderSeedHex: hex.EncodeToString(seed("phone")), NonceHex: hex.EncodeToString(nonce), TimestampMilli: envelope.Timestamp,
		PayloadJSON: string(payload), SigningJSON: string(signing), SignatureB64: base64.StdEncoding.EncodeToString(envelope.Signature), WireJSON: string(wire),
	}

	joinSecret := "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrst"
	key, err := membership.Derive(networkID, joinSecret)
	if err != nil {
		t.Fatalf("vector join secret: %v", err)
	}
	proof := key.Proof(phone.DeviceID(), phone.PublicKey())
	out.Member = MembershipCase{
		NetworkID: networkID, JoinSecret: joinSecret, DeviceID: phone.DeviceID(), RootPublicB64: base64.StdEncoding.EncodeToString(phone.PublicKey()),
		ProofBase64: base64.StdEncoding.EncodeToString(proof), RendezvousName: key.Rendezvous(),
	}

	signedAt := time.Unix(1790000000, 0)
	record, err := discovery.Sign(phone, discovery.PeerRecord{
		NetworkID: networkID, Name: "Pixel", NKNAddress: payloadAddress(payload), WireGuardPublicKey: wgKey,
		VirtualIPs: []string{"10.88.1.2"}, Capabilities: protocol.DefaultCapabilities(), MembershipProof: proof,
		Candidates: []nat.EndpointCandidate{{Type: nat.CandidateReflexive, IP: "203.0.113.5", Port: 51820, Priority: 500, Protocol: "udp", ObservedAt: 1790000000, ExpiresAt: 1790000300}},
	}, 42, 2*time.Minute, signedAt)
	if err != nil {
		t.Fatal(err)
	}
	unsigned := record
	unsigned.Signature = nil
	recordSigning, _ := json.Marshal(unsigned)
	recordWire, _ := record.Marshal()
	out.Record = RecordCase{SignedAtUnix: signedAt.Unix(), SigningJSON: string(recordSigning), WireJSON: string(recordWire)}

	for _, datagram := range [][]byte{{0x01}, seed("datagram")} {
		frame := make([]byte, 2, 2+len(datagram))
		binary.BigEndian.PutUint16(frame, uint16(len(datagram)))
		out.Relay = append(out.Relay, RelayCase{DatagramHex: hex.EncodeToString(datagram), FrameHex: hex.EncodeToString(append(frame, datagram...))})
	}

	cidr := netip.MustParsePrefix("10.88.0.0/16")
	address, err := mesh.AllocateVirtualIP(cidr, networkID, phone.DeviceID(), nil)
	if err != nil {
		t.Fatal(err)
	}
	out.Address = VirtualAddrCase{OverlayCIDR: cidr.String(), NetworkID: networkID, DeviceID: phone.DeviceID(), Address: address.String()}
	return out
}

func payloadAddress(payload []byte) string {
	var request protocol.PairRequest
	_ = json.Unmarshal(payload, &request)
	return request.NKNAddress
}

func TestV1Vectors(t *testing.T) {
	vectors := build(t)
	encoded, err := json.MarshalIndent(vectors, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, '\n')
	path := filepath.Join("testdata", "v1.json")
	if *update {
		if err := os.WriteFile(path, encoded, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	stored, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stored, encoded) {
		t.Fatal("the v1 wire format changed; if deliberate, bump the protocol version or run go test ./internal/vectors -update and document it")
	}

	// The stored vectors are accepted by the production verifiers.
	var envelope protocol.Envelope
	if err := json.Unmarshal([]byte(vectors.Envelope.WireJSON), &envelope); err != nil {
		t.Fatal(err)
	}
	acceptor := &protocol.Acceptor{NetworkID: envelope.NetworkID, LocalDeviceID: envelope.ToDeviceID, Now: func() time.Time { return time.UnixMilli(vectors.Envelope.TimestampMilli) }}
	if err := acceptor.Verify(envelope); err != nil {
		t.Fatalf("vector envelope rejected: %v", err)
	}
	if !ed25519.Verify(envelope.FromPublicKey, []byte(vectors.Envelope.SigningJSON), envelope.Signature) {
		t.Fatal("signature does not cover signing_json")
	}
	tampered := envelope
	tampered.Payload = []byte(`{"token":"x"}`)
	if acceptor.Verify(tampered) == nil {
		t.Fatal("tampered payload accepted")
	}
	record, err := discovery.UnmarshalRecord([]byte(vectors.Record.WireJSON))
	if err != nil {
		t.Fatal(err)
	}
	if err := record.Verify(vectors.Member.NetworkID, time.Unix(vectors.Record.SignedAtUnix, 0)); err != nil {
		t.Fatalf("vector record rejected: %v", err)
	}
	if err := record.Verify(vectors.Member.NetworkID, time.Unix(vectors.Record.SignedAtUnix, 0).Add(10*time.Minute)); err == nil {
		t.Fatal("expired record accepted")
	}
	key, _ := membership.Derive(vectors.Member.NetworkID, vectors.Member.JoinSecret)
	if err := key.Verify(record.DeviceID, record.RootPublicKey, record.MembershipProof); err != nil {
		t.Fatalf("vector membership proof rejected: %v", err)
	}
	if _, err := app.ParsePairInvite(vectors.Invite.URI); err == nil {
		t.Fatal("expired vector invitation accepted")
	}
}
