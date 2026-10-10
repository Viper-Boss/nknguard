package app

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"sync"
	"time"

	"github.com/Viper-Boss/nknguard/pkg/identity"
	"github.com/Viper-Boss/nknguard/pkg/membership"
	"github.com/Viper-Boss/nknguard/pkg/mesh"
	"github.com/Viper-Boss/nknguard/pkg/protocol"
	"github.com/Viper-Boss/nknguard/pkg/signaling"
)

const inviteLifetime = 5 * time.Minute

var ErrPairingOffline = errors.New("NKN 尚未上线，请稍后重试配对；本地管理和已有直连不受影响")

// PairInvite is the QR payload. The token opens only a pending request; it is
// never a membership credential and is consumed after local approval.
type PairInvite struct {
	Version      int       `json:"version"`
	NetworkID    string    `json:"network_id"`
	NASID        string    `json:"nas_id"`
	NASPublicKey []byte    `json:"nas_public_key"`
	NASAddress   string    `json:"nas_address"`
	NASVirtualIP string    `json:"nas_virtual_ip,omitempty"`
	Token        string    `json:"token"`
	ExpiresAt    time.Time `json:"expires_at"`
}

func (i PairInvite) URI() (string, error) {
	raw, err := json.Marshal(i)
	if err != nil {
		return "", err
	}
	return "nknguard://pair/v1?data=" + url.QueryEscape(base64.RawURLEncoding.EncodeToString(raw)), nil
}

func ParsePairInvite(value string) (PairInvite, error) {
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "nknguard" || u.Host != "pair" || u.Path != "/v1" {
		return PairInvite{}, errors.New("pairing: invalid QR invitation")
	}
	raw, err := base64.RawURLEncoding.DecodeString(u.Query().Get("data"))
	if err != nil || len(raw) > 2048 {
		return PairInvite{}, errors.New("pairing: invalid QR data")
	}
	var invite PairInvite
	if err := json.Unmarshal(raw, &invite); err != nil {
		return PairInvite{}, err
	}
	if invite.Version != 1 || !membership.ValidNetworkID(invite.NetworkID) || len(invite.NASPublicKey) != ed25519.PublicKeySize ||
		identity.DeviceIDFromKey(invite.NASPublicKey) != invite.NASID || len(invite.NASAddress) == 0 ||
		len(invite.Token) < 40 || time.Now().After(invite.ExpiresAt) {
		return PairInvite{}, errors.New("pairing: invitation expired or invalid")
	}
	return invite, nil
}

type PendingPair struct {
	DeviceID   string    `json:"device_id"`
	Name       string    `json:"name"`
	Code       string    `json:"code"`
	Requested  time.Time `json:"requested_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	NKNAddress string    `json:"nkn_address"`
}

type pendingRequest struct {
	PendingPair
	request protocol.PairRequest
}

// Pairing owns short-lived invitations and pending approvals for one NAS.
type Pairing struct {
	mu        sync.Mutex
	invite    PairInvite
	pending   map[string]pendingRequest
	node      *Node
	mesh      *mesh.Controller
	transport signaling.Transport
}

func NewPairing(node *Node, controller *mesh.Controller, transport signaling.Transport) *Pairing {
	return &Pairing{node: node, mesh: controller, transport: transport, pending: make(map[string]pendingRequest)}
}

func (p *Pairing) SetTransport(transport signaling.Transport) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.transport = transport
}

func (p *Pairing) owner() bool {
	current, err := p.node.State.LoadMembership()
	return err == nil && current.IsOwner
}

func (p *Pairing) NewInvite() (PairInvite, error) {
	if !p.owner() {
		return PairInvite{}, errors.New("pairing: only the NAS owner can invite devices")
	}
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return PairInvite{}, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pending = make(map[string]pendingRequest)
	if p.transport == nil {
		return PairInvite{}, ErrPairingOffline
	}
	p.invite = PairInvite{
		Version: 1, NetworkID: p.mesh.Config.NetworkID,
		NASID: p.node.Device.DeviceID(), NASPublicKey: p.node.Device.PublicKey(),
		NASAddress: p.transport.LocalAddress(),
		Token:      base64.RawURLEncoding.EncodeToString(token), ExpiresAt: time.Now().Add(inviteLifetime),
	}
	if ip := p.mesh.VirtualIP(); ip.IsValid() {
		p.invite.NASVirtualIP = ip.String()
	}
	return p.invite, nil
}

func (p *Pairing) Pending() []PendingPair {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	out := make([]PendingPair, 0, len(p.pending))
	for id, entry := range p.pending {
		if now.After(entry.ExpiresAt) {
			delete(p.pending, id)
			continue
		}
		out = append(out, entry.PendingPair)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Requested.Before(out[j].Requested) })
	return out
}

// InviteState exposes only a fingerprint and expiry, so browser tabs can hide
// consumed/expired QR codes without fetching or re-creating an invitation.
func (p *Pairing) InviteState() (string, time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.invite.Token == "" || !time.Now().Before(p.invite.ExpiresAt) {
		return "", time.Time{}
	}
	return inviteID(p.invite), p.invite.ExpiresAt
}

func inviteID(invite PairInvite) string {
	sum := sha256.Sum256([]byte(invite.Token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (p *Pairing) HandleRequest(ctx context.Context, envelope protocol.Envelope) error {
	if !p.owner() {
		return errors.New("pairing: this device cannot approve pair requests")
	}
	var request protocol.PairRequest
	if err := envelope.DecodePayload(&request); err != nil {
		return err
	}
	if len(request.Name) == 0 || len(request.Name) > 80 || len(request.NKNAddress) == 0 || len(request.NKNAddress) > 256 {
		return errors.New("pairing: invalid device name or NKN address")
	}
	if source := signaling.Source(ctx); source == "" || source != request.NKNAddress {
		return errors.New("pairing: reply address does not match sender")
	}
	key, err := base64.StdEncoding.DecodeString(request.WireGuardPublicKey)
	if err != nil || len(key) != 32 {
		return errors.New("pairing: invalid WireGuard public key")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if time.Now().After(p.invite.ExpiresAt) || p.invite.Token == "" || subtle.ConstantTimeCompare([]byte(request.Token), []byte(p.invite.Token)) != 1 {
		return errors.New("pairing: invitation expired or invalid")
	}
	if len(p.pending) >= 8 && p.pending[envelope.FromDeviceID].DeviceID == "" {
		return errors.New("pairing: too many pending devices")
	}
	code := PairCode(request.Token, envelope.FromDeviceID, request.WireGuardPublicKey)
	p.pending[envelope.FromDeviceID] = pendingRequest{PendingPair: PendingPair{
		DeviceID: envelope.FromDeviceID, Name: request.Name, Code: code,
		Requested: time.Now(), ExpiresAt: p.invite.ExpiresAt, NKNAddress: request.NKNAddress,
	}, request: request}
	return nil
}

func PairCode(token, deviceID, wgKey string) string {
	codeInput, _ := json.Marshal(struct{ Token, DeviceID, WGKey string }{token, deviceID, wgKey})
	sum := sha256.Sum256(codeInput)
	return fmt.Sprintf("%06d", binary.BigEndian.Uint32(sum[:4])%1000000)
}

// Approve is called only by the local dashboard after the owner compares the
// six-digit code on the client. The shared network key is sent inside NKN's
// encrypted message, never in the QR, dashboard response, or log.
func (p *Pairing) Approve(ctx context.Context, deviceID string) error {
	if !p.owner() {
		return errors.New("pairing: only the NAS owner can approve devices")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	entry, ok := p.pending[deviceID]
	if !ok || time.Now().After(entry.ExpiresAt) {
		return errors.New("pairing: request expired or unknown")
	}
	if p.transport == nil {
		return ErrPairingOffline
	}
	if err := p.cleanPendingLocked(ctx); err != nil {
		return err
	}
	secret, err := p.node.JoinSecret()
	if err != nil {
		return err
	}
	current, err := p.node.State.LoadMembership()
	if err != nil {
		return err
	}
	for _, member := range current.Members {
		if member == deviceID {
			return errors.New("pairing: device already approved")
		}
	}
	approval := protocol.PairApproval{JoinSecret: secret, NASID: p.node.Device.DeviceID(), NASAddress: p.transport.LocalAddress(), InviteToken: entry.request.Token}
	envelope, err := protocol.Seal(p.node.Device, current.NetworkID, deviceID, protocol.TypePairApproval, approval)
	if err != nil {
		return err
	}
	// Persist and admit before the secret leaves: a device must never hold
	// the join secret while this NAS does not list it, or its first
	// introduction would be refused as unapproved.
	current.Members = append(current.Members, deviceID)
	if current.MemberAddresses == nil {
		current.MemberAddresses = make(map[string]string)
	}
	current.MemberAddresses[deviceID] = entry.NKNAddress
	if err := p.node.State.SaveMembership(current); err != nil {
		return err
	}
	p.mesh.ApproveDevice(deviceID)
	if err := p.transport.SendAddress(ctx, entry.NKNAddress, envelope); err != nil {
		// Undo, and keep the request pending so the owner can retry.
		rollbackErr := p.revokeLocked(ctx, deviceID)
		return errors.Join(fmt.Errorf("pairing: approval not delivered, try again: %w", err), rollbackErr)
	}
	delete(p.pending, deviceID)
	p.invite = PairInvite{}
	p.mesh.RememberApprovedAddress(deviceID, entry.NKNAddress)
	return nil
}

func (p *Pairing) Revoke(ctx context.Context, deviceID string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.revokeLocked(ctx, deviceID)
}

func (p *Pairing) revokeLocked(ctx context.Context, deviceID string) error {
	if !p.owner() {
		return errors.New("pairing: only the NAS owner can revoke devices")
	}
	current, err := p.node.State.LoadMembership()
	if err != nil {
		return err
	}
	if deviceID == p.node.Device.DeviceID() {
		return errors.New("pairing: cannot revoke this NAS")
	}
	filtered := current.Members[:0]
	for _, member := range current.Members {
		if member != deviceID {
			filtered = append(filtered, member)
		}
	}
	current.Members = filtered
	delete(current.MemberAddresses, deviceID)
	if key := p.mesh.PeerPublicKey(deviceID); key != "" {
		found := false
		for _, pending := range current.PendingRemovals {
			if pending == key {
				found = true
			}
		}
		if !found {
			current.PendingRemovals = append(current.PendingRemovals, key)
		}
	}
	if err := p.node.State.SaveMembership(current); err != nil {
		return err
	}
	if _, err := p.mesh.RevokeDevice(ctx, deviceID); err != nil {
		return err
	}
	if err := p.mesh.PruneUntrackedPeers(ctx); err != nil {
		return err
	}
	return p.cleanPendingLocked(ctx)
}

// CleanPending runs before any cached peer is installed after a restart.
func (p *Pairing) CleanPending(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cleanPendingLocked(ctx)
}

func (p *Pairing) cleanPendingLocked(ctx context.Context) error {
	current, err := p.node.State.LoadMembership()
	if err != nil {
		return err
	}
	if len(current.PendingRemovals) == 0 {
		return nil
	}
	for _, key := range current.PendingRemovals {
		if err := p.mesh.RemoveRevokedKey(ctx, key); err != nil {
			return err
		}
	}
	current.PendingRemovals = nil
	return p.node.State.SaveMembership(current)
}
