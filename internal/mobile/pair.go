package mobile

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"time"

	"github.com/Viper-Boss/nknguard/internal/app"
	"github.com/Viper-Boss/nknguard/internal/state"
	"github.com/Viper-Boss/nknguard/pkg/identity"
	"github.com/Viper-Boss/nknguard/pkg/membership"
	"github.com/Viper-Boss/nknguard/pkg/protocol"
	"github.com/Viper-Boss/nknguard/pkg/wireguard"
)

type pairArgs struct {
	URI  string `json:"uri"`
	Name string `json:"name"`
}

// Pairing stages reported in pair_status events.
const (
	PairConnecting = "connecting"
	PairWaiting    = "waiting"
	PairApproved   = "approved"
	PairFailed     = "failed"
)

// PairStatus is the payload of a pair_status event.
type PairStatus struct {
	Stage      string    `json:"stage"`
	DeviceID   string    `json:"device_id"`
	NASID      string    `json:"nas_id"`
	NASAddress string    `json:"nas_address"`
	Code       string    `json:"code,omitempty"`
	ExpiresAt  time.Time `json:"expires_at"`
	Error      string    `json:"error,omitempty"`
}

// pairResend is how often an unanswered request is sent again. NKN may drop a
// message while a node reconnects; the NAS treats a repeat of the same request
// as the same pending entry with the same code.
const pairResend = 15 * time.Second

func (a *Agent) pair(ctx context.Context, args pairArgs) (any, error) {
	invite, err := app.ParsePairInvite(strings.TrimSpace(args.URI))
	if err != nil {
		return nil, errInvalidInvite
	}
	if name := cleanName(args.Name); name != "" {
		a.mu.Lock()
		a.name = name
		a.mu.Unlock()
	}
	device, name, err := a.identity()
	if err != nil {
		return nil, err
	}
	profile, paired, err := loadProfile(a.StateDir)
	if err != nil {
		return nil, err
	}
	if paired && profile.RevokedAt == nil && a.Secrets.Has(SecretJoinSecret) {
		return nil, errors.New("本机已与 NAS 配对；如需重新配对，请先解除配对")
	}
	a.mu.Lock()
	if a.session != nil {
		a.mu.Unlock()
		return nil, errors.New("请先断开连接再配对")
	}
	if a.pairCancel != nil {
		a.mu.Unlock()
		return nil, errors.New("已有配对申请正在进行")
	}
	deadline := invite.ExpiresAt
	if a.PairWait > 0 && time.Now().Add(a.PairWait).Before(deadline) {
		deadline = time.Now().Add(a.PairWait)
	}
	pairCtx, cancel := context.WithDeadline(ctx, deadline)
	done := make(chan struct{})
	a.pairCancel, a.pairDone = cancel, done
	a.mu.Unlock()

	status := PairStatus{Stage: PairConnecting, DeviceID: device.DeviceID(), NASID: invite.NASID, NASAddress: invite.NASAddress, ExpiresAt: invite.ExpiresAt}
	go func() {
		defer close(done)
		defer cancel()
		err := a.runPairing(pairCtx, invite, device, name, status)
		a.mu.Lock()
		if a.pairDone == done {
			a.pairCancel, a.pairDone = nil, nil
		}
		a.mu.Unlock()
		if err != nil {
			status.Stage = PairFailed
			status.Error = pairError(pairCtx, err)
			a.Logger.Info("pairing did not complete", "component", "pairing", "error", status.Error)
			a.emit("pair_status", status)
		}
	}()
	return status, nil
}

func pairError(ctx context.Context, err error) string {
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return "二维码已过期或 NAS 未批准；请在 NAS 面板重新生成二维码"
	case errors.Is(ctx.Err(), context.Canceled):
		return "配对已取消"
	default:
		return err.Error()
	}
}

func (a *Agent) cancelPairing() {
	a.mu.Lock()
	cancel, done := a.pairCancel, a.pairDone
	a.mu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
}

// runPairing is the Android counterpart of the CLI's pairDeviceNKN, with the
// same checks in the same order: the approval must be signed by the NAS
// identity pinned in the QR code, bound to this invitation's token and NAS
// address, and carry a join secret that derives a membership key.
func (a *Agent) runPairing(ctx context.Context, invite app.PairInvite, device *identity.DeviceIdentity, name string, status PairStatus) error {
	a.emit("pair_status", status)
	wgKey, err := wireguard.EnsureKeyPair(a.Secrets)
	if err != nil {
		return err
	}
	seed, err := a.nknSeed()
	if err != nil {
		return err
	}
	if a.OpenPlane == nil {
		return errors.New("this core was built without NKN support")
	}
	a.mu.Lock()
	seedRPC := a.seedRPC
	a.mu.Unlock()
	plane, err := a.OpenPlane(ctx, seed, seedRPC)
	if err != nil {
		return err
	}
	defer func() { _ = plane.Close() }()
	transport := plane.Signaling
	request := protocol.PairRequest{Token: invite.Token, Name: name, NKNAddress: transport.LocalAddress(), WireGuardPublicKey: wgKey}
	send := func() error {
		envelope, err := protocol.Seal(device, invite.NetworkID, invite.NASID, protocol.TypePairRequest, request)
		if err != nil {
			return err
		}
		return transport.SendAddress(ctx, invite.NASAddress, envelope)
	}
	if err := send(); err != nil {
		return err
	}
	status.Stage = PairWaiting
	status.Code = app.PairCode(invite.Token, device.DeviceID(), wgKey)
	a.emit("pair_status", status)
	a.Logger.Info("pairing request sent", "component", "pairing", "nas", invite.NASID)

	acceptor := &protocol.Acceptor{NetworkID: invite.NetworkID, LocalDeviceID: device.DeviceID(), Replay: protocol.NewReplayCache(0, 0)}
	resend := time.NewTicker(pairResend)
	defer resend.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-resend.C:
			_ = send()
		case inbound, ok := <-transport.Receive():
			if !ok {
				return errors.New("NKN 连接已断开")
			}
			message := inbound.Envelope
			if message.Type != protocol.TypePairApproval || message.FromDeviceID != invite.NASID ||
				!bytes.Equal(message.FromPublicKey, invite.NASPublicKey) || acceptor.Verify(message) != nil {
				continue
			}
			var approval protocol.PairApproval
			if message.DecodePayload(&approval) != nil || approval.InviteToken != invite.Token ||
				approval.NASID != invite.NASID || approval.NASAddress != invite.NASAddress {
				continue
			}
			if _, err := membership.Derive(invite.NetworkID, approval.JoinSecret); err != nil {
				continue
			}
			if err := a.savePairing(invite, device, name, approval.JoinSecret); err != nil {
				return err
			}
			status.Stage = PairApproved
			a.emit("pair_status", status)
			a.Logger.Info("pairing approved", "component", "pairing", "nas", invite.NASID)
			return nil
		}
	}
}

func (a *Agent) savePairing(invite app.PairInvite, device *identity.DeviceIdentity, name, joinSecret string) error {
	if err := removeState(a.StateDir); err != nil {
		return err
	}
	// The secret goes to the app (and its encrypted store) before anything
	// on disk says the phone is paired, so a crash in between leaves an
	// unpaired phone rather than a paired one without its secret.
	if err := a.Secrets.WriteSecret(SecretJoinSecret, []byte(strings.TrimSpace(joinSecret))); err != nil {
		return err
	}
	if err := a.store().SaveMembership(state.Membership{
		NetworkID: invite.NetworkID, DeviceID: device.DeviceID(), JoinedAt: time.Now().UTC(), Members: []string{invite.NASID},
	}); err != nil {
		return err
	}
	return saveProfile(a.StateDir, Profile{
		NetworkID: invite.NetworkID, NASID: invite.NASID, NASPublicKey: invite.NASPublicKey,
		NASAddress: invite.NASAddress, NASVirtualIP: invite.NASVirtualIP, DeviceName: name, PairedAt: time.Now().UTC(),
	})
}
