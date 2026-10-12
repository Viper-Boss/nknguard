//go:build libp2pdht

package dht

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"github.com/Viper-Boss/nknguard/pkg/discovery"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"io"
	"time"
)

const PrivateRecordProtocol = protocol.ID("/nknguard/record/2.0.0")

// An untrusted public routing neighbor must not see the private record we
// submit to authenticate a lookup. Production keys derive from the private
// membership key, never a legacy public topic. Bind both peers and direction.
func (b *Backend) privateRecordCipher() (cipher.AEAD, error) {
	key := sha256.Sum256([]byte("NKNGuard-private-record-v2:" + b.opts.Rendezvous))
	secret := b.opts.PrivateRecordKey
	if len(secret) == 0 {
		if b.opts.RecordAllowed != nil {
			return nil, errors.New("private record encryption key required")
		}
		secret = key[:]
	}
	block, err := aes.NewCipher(secret)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
func (b *Backend) sealPrivate(raw []byte, from, to peer.ID, role string) ([]byte, error) {
	aead, err := b.privateRecordCipher()
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, raw, []byte(role+":"+from.String()+":"+to.String())), nil
}
func (b *Backend) openPrivate(raw []byte, from, to peer.ID, role string) ([]byte, error) {
	aead, err := b.privateRecordCipher()
	if err != nil {
		return nil, err
	}
	if len(raw) < aead.NonceSize()+aead.Overhead() || len(raw) > discovery.MaxRecordBytes+64 {
		return nil, errors.New("invalid private record ciphertext")
	}
	return aead.Open(nil, raw[:aead.NonceSize()], raw[aead.NonceSize():], []byte(role+":"+from.String()+":"+to.String()))
}

func (b *Backend) servePrivateRecord(stream network.Stream) {
	select {
	case b.slots <- struct{}{}:
	default:
		_ = stream.Reset()
		return
	}
	defer func() { <-b.slots }()
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(10 * time.Second))
	raw, err := io.ReadAll(io.LimitReader(stream, discovery.MaxRecordBytes+65))
	if err == nil {
		raw, err = b.openPrivate(raw, stream.Conn().RemotePeer(), b.host.ID(), "request")
	}
	r, errRecord := discovery.UnmarshalRecord(raw)
	if err != nil || errRecord != nil || (b.opts.RecordAllowed != nil && !b.opts.RecordAllowed(r)) {
		_ = stream.Reset()
		return
	}
	bound := false
	for _, address := range r.DHTAddresses {
		if info, err := parse(address); err == nil && info.ID == stream.Conn().RemotePeer() {
			bound = true
			break
		}
	}
	if !bound && b.opts.RecordAllowed != nil {
		_ = stream.Reset()
		return
	}
	b.mu.RLock()
	own := append([]byte(nil), b.own...)
	b.mu.RUnlock()
	if len(own) > 0 {
		if sealed, err := b.sealPrivate(own, b.host.ID(), stream.Conn().RemotePeer(), "response"); err == nil {
			_, _ = stream.Write(sealed)
		}
	}
}
