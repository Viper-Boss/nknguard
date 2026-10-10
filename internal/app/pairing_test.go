package app

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/Viper-Boss/nknguard/internal/config"
	"github.com/Viper-Boss/nknguard/pkg/identity"
	"github.com/Viper-Boss/nknguard/pkg/mesh"
	"github.com/Viper-Boss/nknguard/pkg/protocol"
	"github.com/Viper-Boss/nknguard/pkg/signaling"
)

func TestOwnerApprovedPairingAndRevocation(t *testing.T) {
	cfg := config.Default()
	cfg.Paths.StateDir = t.TempDir()
	node, err := OpenNode(cfg)
	if err != nil {
		t.Fatal(err)
	}
	networkID, secret, err := node.CreateNetwork()
	if err != nil {
		t.Fatal(err)
	}
	client, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	switcher := signaling.NewSwitch()
	nasWire := switcher.Attach(node.Device.DeviceID())
	clientWire := switcher.Attach(client.DeviceID())
	controller := mesh.New()
	controller.Config.NetworkID = networkID
	controller.Config.RequireApproval = true
	pairing := NewPairing(node, controller, nasWire)
	invite, err := pairing.NewInvite()
	if err != nil {
		t.Fatal(err)
	}
	if id, expiry := pairing.InviteState(); id == "" || !expiry.Equal(invite.ExpiresAt) {
		t.Fatal("active invitation status missing")
	}
	uri, err := invite.URI()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(uri, secret) {
		t.Fatal("QR leaked the join secret")
	}
	parsed, err := ParsePairInvite(uri)
	if err != nil || parsed.NASID != node.Device.DeviceID() {
		t.Fatalf("parse: %+v %v", parsed, err)
	}
	wgKey := base64.StdEncoding.EncodeToString(make([]byte, 32))
	request := protocol.PairRequest{Token: parsed.Token, Name: "phone", NKNAddress: client.DeviceID(), WireGuardPublicKey: wgKey}
	envelope, err := protocol.Seal(client, networkID, node.Device.DeviceID(), protocol.TypePairRequest, request)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher := &signaling.Dispatcher{Acceptor: &protocol.Acceptor{NetworkID: networkID, LocalDeviceID: node.Device.DeviceID()}, Open: map[protocol.MessageType]bool{protocol.TypePairRequest: true}}
	dispatcher.Handle(protocol.TypePairRequest, pairing.HandleRequest)
	if err := dispatcher.Dispatch(context.Background(), signaling.Inbound{Envelope: envelope, Source: "other-nkn-address"}); err == nil {
		t.Fatal("request with a substituted reply address was accepted")
	}
	envelope, err = protocol.Seal(client, networkID, node.Device.DeviceID(), protocol.TypePairRequest, request)
	if err != nil {
		t.Fatal(err)
	}
	if err := dispatcher.Dispatch(context.Background(), signaling.Inbound{Envelope: envelope, Source: client.DeviceID()}); err != nil {
		t.Fatal(err)
	}
	pending := pairing.Pending()
	if len(pending) != 1 || pending[0].Code != PairCode(parsed.Token, client.DeviceID(), wgKey) {
		t.Fatalf("pending: %+v", pending)
	}
	if controller.Authorized(client.DeviceID()) {
		t.Fatal("pending device was authorized")
	}
	if err := pairing.Approve(context.Background(), client.DeviceID()); err != nil {
		t.Fatal(err)
	}
	if !controller.Authorized(client.DeviceID()) {
		t.Fatal("approved device was not authorized")
	}
	if id, _ := pairing.InviteState(); id != "" {
		t.Fatal("consumed invitation still active")
	}
	storedApproval, err := node.State.LoadMembership()
	if err != nil || storedApproval.MemberAddresses[client.DeviceID()] != client.DeviceID() {
		t.Fatal("approved address not persisted")
	}
	select {
	case inbound := <-clientWire.Receive():
		if inbound.Envelope.Type != protocol.TypePairApproval {
			t.Fatalf("type: %s", inbound.Envelope.Type)
		}
		var approval protocol.PairApproval
		if err := inbound.Envelope.DecodePayload(&approval); err != nil {
			t.Fatal(err)
		}
		if approval.JoinSecret != secret || approval.InviteToken != parsed.Token {
			t.Fatal("approval was not bound to invitation")
		}
	case <-time.After(time.Second):
		t.Fatal("approval not delivered")
	}
	if err := pairing.Revoke(context.Background(), client.DeviceID()); err != nil {
		t.Fatal(err)
	}
	if controller.Authorized(client.DeviceID()) {
		t.Fatal("revoked device is still authorized")
	}
	stored, err := node.State.LoadMembership()
	if err != nil || len(stored.Members) != 0 || len(stored.MemberAddresses) != 0 {
		t.Fatalf("stored approval: %+v %v", stored, err)
	}
}

func TestExpiredInvitationIsNotAdvertised(t *testing.T) {
	pairing := &Pairing{invite: PairInvite{Token: "test-token", ExpiresAt: time.Now().Add(-time.Second)}}
	if id, expiry := pairing.InviteState(); id != "" || !expiry.IsZero() {
		t.Fatal("expired invitation advertised as active")
	}
}

func TestDashboardHostRestriction(t *testing.T) {
	for _, host := range []string{"127.0.0.1:7878", "localhost:7878", "[::1]:7878"} {
		if !validDashboardHost(host, "127.0.0.1:7878") {
			t.Errorf("rejected %s", host)
		}
	}
	for _, host := range []string{"evil.example:7878", "127.0.0.1:8080", "nas.local:7878"} {
		if validDashboardHost(host, "127.0.0.1:7878") {
			t.Errorf("accepted %s", host)
		}
	}
}

func TestApprovalIsRolledBackWhenUndelivered(t *testing.T) {
	cfg := config.Default()
	cfg.Paths.StateDir = t.TempDir()
	node, err := OpenNode(cfg)
	if err != nil {
		t.Fatal(err)
	}
	networkID, _, err := node.CreateNetwork()
	if err != nil {
		t.Fatal(err)
	}
	client, _ := identity.Generate()
	switcher := signaling.NewSwitch()
	nasWire := switcher.Attach(node.Device.DeviceID())
	controller := mesh.New()
	controller.Config.NetworkID = networkID
	controller.Config.RequireApproval = true
	pairing := NewPairing(node, controller, nasWire)
	invite, _ := pairing.NewInvite()
	wgKey := base64.StdEncoding.EncodeToString(make([]byte, 32))
	// The client's address is not attached to the switch, so delivery fails.
	request := protocol.PairRequest{Token: invite.Token, Name: "phone", NKNAddress: client.DeviceID(), WireGuardPublicKey: wgKey}
	envelope, _ := protocol.Seal(client, networkID, node.Device.DeviceID(), protocol.TypePairRequest, request)
	ctx := context.Background()
	dispatcher := &signaling.Dispatcher{Acceptor: &protocol.Acceptor{NetworkID: networkID, LocalDeviceID: node.Device.DeviceID()}, Open: map[protocol.MessageType]bool{protocol.TypePairRequest: true}}
	dispatcher.Handle(protocol.TypePairRequest, pairing.HandleRequest)
	if err := dispatcher.Dispatch(ctx, signaling.Inbound{Envelope: envelope, Source: client.DeviceID()}); err != nil {
		t.Fatal(err)
	}
	if err := pairing.Approve(ctx, client.DeviceID()); err == nil {
		t.Fatal("undelivered approval reported success")
	}
	if controller.Authorized(client.DeviceID()) {
		t.Fatal("device stayed authorized after an undelivered approval")
	}
	stored, _ := node.State.LoadMembership()
	if len(stored.Members) != 0 {
		t.Fatalf("members after rollback: %v", stored.Members)
	}
	if len(pairing.Pending()) != 1 {
		t.Fatal("request should stay pending so the owner can retry")
	}
	// Once the client is reachable, approval goes through.
	switcher.Attach(client.DeviceID())
	if err := pairing.Approve(ctx, client.DeviceID()); err != nil {
		t.Fatal(err)
	}
	if !controller.Authorized(client.DeviceID()) {
		t.Fatal("retry did not approve")
	}
}
