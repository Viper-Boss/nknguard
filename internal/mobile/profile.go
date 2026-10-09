package mobile

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// Profile is what the phone remembers about the NAS it paired with. None of
// it is secret: the join secret lives in the SecretStore.
type Profile struct {
	NetworkID    string    `json:"network_id"`
	NASID        string    `json:"nas_id"`
	NASPublicKey []byte    `json:"nas_public_key"`
	NASAddress   string    `json:"nas_address"`
	NASVirtualIP string    `json:"nas_virtual_ip,omitempty"`
	DeviceName   string    `json:"device_name"`
	PairedAt     time.Time `json:"paired_at"`
	// RevokedAt is set when the NAS, speaking with its pinned identity, said
	// this device is no longer approved. The phone then refuses to connect
	// until it is paired again.
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

const profileFile = "profile.json"

func loadProfile(dir string) (Profile, bool, error) {
	raw, err := os.ReadFile(filepath.Join(dir, profileFile))
	if errors.Is(err, fs.ErrNotExist) {
		return Profile{}, false, nil
	}
	if err != nil {
		return Profile{}, false, err
	}
	var profile Profile
	if err := json.Unmarshal(raw, &profile); err != nil {
		return Profile{}, false, err
	}
	return profile, profile.NetworkID != "", nil
}

func saveProfile(dir string, profile Profile) error {
	raw, err := json.MarshalIndent(profile, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	temporary := filepath.Join(dir, profileFile+".tmp")
	if err := os.WriteFile(temporary, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(temporary, filepath.Join(dir, profileFile))
}

func removeState(dir string) error {
	for _, name := range []string{profileFile, "membership.json", "peers.json", "links.json"} {
		if err := os.Remove(filepath.Join(dir, name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return nil
}
