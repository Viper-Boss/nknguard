package app

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Viper-Boss/nknguard/internal/config"
	"github.com/Viper-Boss/nknguard/internal/state"
	"github.com/Viper-Boss/nknguard/pkg/identity"
	"github.com/Viper-Boss/nknguard/pkg/membership"
)

// JoinSecretName is the keystore entry for the join secret. It is a secret:
// never in the config file, never in state/membership.json, never logged.
const JoinSecretName = "join.secret"

const dashboardKeyName = "dashboard.key"

// DashboardKey is an independent local administrator password. Only the NAS
// operator can read it from the owner-only keystore.
func (n *Node) DashboardKey() (string, error) {
	stored, err := n.Keystore.ReadSecret(dashboardKeyName)
	if err == nil {
		return string(stored), nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", err
	}
	encoded := base64.RawURLEncoding.EncodeToString(key)
	if err := n.Keystore.WriteSecret(dashboardKeyName, []byte(encoded)); err != nil {
		return "", err
	}
	return encoded, nil
}

// Node is the on-disk identity of this machine: keystore, root identity, state.
type Node struct {
	Config   config.Config
	Keystore *identity.Keystore
	Device   *identity.DeviceIdentity
	State    *state.Store
}

// OpenNode loads (creating on first use) the root identity.
func OpenNode(cfg config.Config) (*Node, error) {
	keystore := identity.NewKeystore(cfg.KeystoreDir())
	device, err := keystore.LoadOrCreateRoot()
	if err != nil {
		return nil, err
	}
	return &Node{Config: cfg, Keystore: keystore, Device: device, State: state.New(cfg.Paths.StateDir)}, nil
}

// CreateNetwork makes a fresh network and joins it.
func (n *Node) CreateNetwork() (networkID, secret string, err error) {
	if networkID, err = membership.NewNetworkID(); err != nil {
		return "", "", err
	}
	if secret, err = membership.NewJoinSecret(); err != nil {
		return "", "", err
	}
	if err := n.Join(networkID, secret); err != nil {
		return "", "", err
	}
	current, err := n.State.LoadMembership()
	if err != nil {
		return "", "", err
	}
	current.IsOwner = true
	return networkID, secret, n.State.SaveMembership(current)
}

// Join records membership of a network.
func (n *Node) Join(networkID, secret string) error {
	secret = strings.TrimSpace(secret)
	if _, err := membership.Derive(networkID, secret); err != nil {
		return err
	}
	current, err := n.State.LoadMembership()
	if err != nil {
		return err
	}
	if current.NetworkID != "" && current.NetworkID != networkID {
		return fmt.Errorf("already a member of %s; this version supports one network per node — run `nknguard leave` first", current.NetworkID)
	}
	if err := n.Keystore.WriteSecret(JoinSecretName, []byte(secret)); err != nil {
		return err
	}
	return n.State.SaveMembership(state.Membership{NetworkID: networkID, DeviceID: n.Device.DeviceID(), JoinedAt: time.Now().UTC()})
}

// ErrNotJoined means no membership is on disk.
var ErrNotJoined = errors.New("not a member of any network — run `nknguard init` or `nknguard join`")

// MembershipKey loads the derived membership key.
func (n *Node) MembershipKey() (*membership.Key, state.Membership, error) {
	current, err := n.State.LoadMembership()
	if err != nil {
		return nil, current, err
	}
	if current.NetworkID == "" {
		return nil, current, ErrNotJoined
	}
	secret, err := n.Keystore.ReadSecret(JoinSecretName)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, current, ErrNotJoined
	}
	if err != nil {
		return nil, current, err
	}
	key, err := membership.Derive(current.NetworkID, string(secret))
	return key, current, err
}

// JoinSecret returns the stored secret, for `nknguard invite`. The caller
// prints it to the operator's terminal and nowhere else.
func (n *Node) JoinSecret() (string, error) {
	secret, err := n.Keystore.ReadSecret(JoinSecretName)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(secret)), nil
}

// Leave forgets the network: the join secret and the membership record. The
// device identity is kept, so rejoining later keeps the same device id and the
// same overlay address.
func (n *Node) Leave() error {
	for _, path := range []string{
		filepath.Join(n.Keystore.Dir(), JoinSecretName),
		filepath.Join(n.State.Dir(), "membership.json"),
		filepath.Join(n.State.Dir(), "peers.json"),
	} {
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return nil
}
