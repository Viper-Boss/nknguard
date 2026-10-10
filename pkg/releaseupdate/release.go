// Package releaseupdate reads the maintainer-signed GitHub release catalogue.
// Checking is explicit; it never installs a downloaded executable.
package releaseupdate

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"golang.org/x/mod/semver"
)

const Repository = "Viper-Boss/nknguard"
const ReleaseURL = "https://github.com/" + Repository + "/releases"
const PublicKeyHex = "f9e46b45a2cd1a249468fda1529fa52d13179c4d9effac54f8b0d0b91a782649"
const MaxPackageSize int64 = 160 << 20

type Asset struct {
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Arch   string `json:"arch"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type Manifest struct {
	Version string  `json:"version"`
	Assets  []Asset `json:"assets"`
}

type Result struct {
	Current     string    `json:"current"`
	Latest      string    `json:"latest"`
	Available   bool      `json:"available"`
	ReleaseURL  string    `json:"release_url"`
	DownloadURL string    `json:"download_url,omitempty"`
	Asset       *Asset    `json:"asset,omitempty"`
	CheckedAt   time.Time `json:"checked_at"`
}

func VerifyManifest(raw, signature []byte) (Manifest, error) {
	key, _ := hex.DecodeString(PublicKeyHex)
	return verifyManifest(raw, signature, key)
}

func verifyManifest(raw, signature, key []byte) (Manifest, error) {
	var m Manifest
	if len(raw) > 1<<20 || !ed25519.Verify(key, raw, signature) {
		return m, errors.New("release signature invalid")
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return m, err
	}
	if !semver.IsValid(version(m.Version)) || len(m.Assets) == 0 || len(m.Assets) > 32 {
		return m, errors.New("invalid release manifest")
	}
	seen := map[string]bool{}
	for _, a := range m.Assets {
		digest, err := hex.DecodeString(a.SHA256)
		if a.Name != path.Base(a.Name) || strings.ContainsAny(a.Name, "\\?#%\r\n") || a.Name == "." || a.Name == ".." || a.Size <= 0 || a.Size > MaxPackageSize || err != nil || len(digest) != sha256.Size || seen[a.Name] {
			return m, errors.New("invalid release asset")
		}
		seen[a.Name] = true
	}
	return m, nil
}

func version(v string) string { return "v" + strings.TrimPrefix(v, "v") }
func Newer(latest, current string) bool {
	return semver.IsValid(version(latest)) && (!semver.IsValid(version(current)) || semver.Compare(version(latest), version(current)) > 0)
}

func Fetch(ctx context.Context, client *http.Client, location string, limit int64) ([]byte, error) {
	u, err := url.Parse(location)
	if err != nil || u.Scheme != "https" || u.User != nil || !allowedURL(u) {
		return nil, errors.New("untrusted release URL")
	}
	if client == nil {
		client = &http.Client{Timeout: 25 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, location, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "NKNGuard-update-check")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub returned %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, errors.New("release response too large")
	}
	return raw, nil
}

func allowedURL(u *url.URL) bool {
	if u.Host != "github.com" && u.Host != "api.github.com" {
		return false
	}
	if u.Host == "api.github.com" {
		return strings.HasPrefix(u.Path, "/repos/"+Repository+"/releases")
	}
	return strings.HasPrefix(u.Path, "/"+Repository+"/releases/")
}

// Check includes preview releases because this project currently ships previews.
// Unsigned older releases are shown only as a release page, never executable downloads.
func Check(ctx context.Context, current, kind, arch string) (Result, error) {
	r := Result{Current: current, ReleaseURL: ReleaseURL, CheckedAt: time.Now().UTC()}
	raw, err := Fetch(ctx, nil, "https://api.github.com/repos/"+Repository+"/releases?per_page=20", 1<<20)
	if err != nil {
		return r, err
	}
	var releases []struct {
		Tag    string `json:"tag_name"`
		Draft  bool   `json:"draft"`
		Assets []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err = json.Unmarshal(raw, &releases); err != nil {
		return r, err
	}
	for _, release := range releases {
		if release.Draft || !semver.IsValid(version(release.Tag)) || (r.Latest != "" && !Newer(release.Tag, r.Latest)) {
			continue
		}
		r.Latest, r.ReleaseURL = release.Tag, ReleaseURL+"/tag/"+release.Tag
		r.Asset, r.DownloadURL = nil, ""
		locations := map[string]string{}
		for _, a := range release.Assets {
			locations[a.Name] = a.URL
		}
		if locations["release.json"] == "" || locations["release.json.sig"] == "" {
			continue
		}
		body, e := Fetch(ctx, nil, locations["release.json"], 1<<20)
		if e != nil {
			return r, e
		}
		sig, e := Fetch(ctx, nil, locations["release.json.sig"], ed25519.SignatureSize)
		if e != nil {
			return r, e
		}
		m, e := VerifyManifest(body, sig)
		if e != nil || version(m.Version) != version(release.Tag) {
			return r, errors.New("release catalogue failed verification")
		}
		for _, a := range m.Assets {
			if a.Kind == kind && a.Arch == arch && locations[a.Name] != "" {
				asset := a
				r.Asset, r.DownloadURL = &asset, locations[a.Name]
				break
			}
		}
	}
	if r.Latest == "" {
		return r, errors.New("no published release")
	}
	r.Available = Newer(r.Latest, current)
	return r, nil
}
