//go:build nknsdk

package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/Viper-Boss/nknguard/internal/config"
	"github.com/Viper-Boss/nknguard/pkg/membership"
	"github.com/Viper-Boss/nknguard/pkg/nknclient"
	"github.com/Viper-Boss/nknguard/pkg/protocol"
	"github.com/Viper-Boss/nknguard/pkg/signaling/nknsignal"
	"github.com/Viper-Boss/nknguard/pkg/wireguard"
)

func init() { pairDeviceFactory = pairDeviceNKN }

func pairDeviceNKN(ctx context.Context, cfg config.Config, invitation string, progress io.Writer) (PairResult, error) {
	invite, err := ParsePairInvite(invitation)
	if err != nil {
		return PairResult{}, err
	}
	node, err := OpenNode(cfg)
	if err != nil {
		return PairResult{}, err
	}
	if current, err := node.State.LoadMembership(); err != nil {
		return PairResult{}, err
	} else if current.NetworkID != "" {
		return PairResult{}, errors.New("pairing: this device has already joined a network")
	}
	wgKey, err := wireguard.EnsureKeyPair(wireguard.FromIdentityKeystore(node.Keystore))
	if err != nil {
		return PairResult{}, err
	}
	seed, err := nknSeed(node.Keystore)
	if err != nil {
		return PairResult{}, err
	}
	client, err := nknclient.Open(ctx, nknclient.Options{Seed: seed, SeedRPC: cfg.NKN.SeedRPC})
	if err != nil {
		return PairResult{}, err
	}
	transport := nknsignal.New(client)
	defer transport.Close()
	request := protocol.PairRequest{Token: invite.Token, Name: cfg.Device.Name, NKNAddress: transport.LocalAddress(), WireGuardPublicKey: wgKey}
	envelope, err := protocol.Seal(node.Device, invite.NetworkID, invite.NASID, protocol.TypePairRequest, request)
	if err != nil {
		return PairResult{}, err
	}
	if err := transport.SendAddress(ctx, invite.NASAddress, envelope); err != nil {
		return PairResult{}, err
	}
	fmt.Fprintf(progress, "请在 NAS 面板核对并批准：设备 %s，验证码 %s\n", node.Device.DeviceID(), PairCode(invite.Token, node.Device.DeviceID(), wgKey))
	waitCtx, cancel := context.WithDeadline(ctx, invite.ExpiresAt)
	defer cancel()
	acceptor := &protocol.Acceptor{NetworkID: invite.NetworkID, LocalDeviceID: node.Device.DeviceID(), Replay: protocol.NewReplayCache(0, 0)}
	for {
		select {
		case <-waitCtx.Done():
			return PairResult{}, fmt.Errorf("pairing: approval not received: %w", waitCtx.Err())
		case inbound, ok := <-transport.Receive():
			if !ok {
				return PairResult{}, errors.New("pairing: NKN connection closed")
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
			if err := node.Join(invite.NetworkID, approval.JoinSecret); err != nil {
				return PairResult{}, err
			}
			current, err := node.State.LoadMembership()
			if err != nil {
				return PairResult{}, err
			}
			current.Members = []string{invite.NASID}
			if err := node.State.SaveMembership(current); err != nil {
				return PairResult{}, err
			}
			return PairResult{NetworkID: invite.NetworkID, NASID: invite.NASID, NASAddress: invite.NASAddress}, nil
		}
	}
}
