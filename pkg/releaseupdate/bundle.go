package releaseupdate

import (
	"archive/zip"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// StageBundle accepts exactly the catalogue, detached signature and one payload.
// Files are streamed into an owner-only directory; untrusted paths are never extracted.
func StageBundle(source, destination, current, kind, arch string) (Asset, string, error) {
	var empty Asset
	z, err := zip.OpenReader(source)
	if err != nil {
		return empty, "", err
	}
	defer z.Close()
	if len(z.File) != 3 {
		return empty, "", errors.New("update bundle must contain three files")
	}
	files := map[string]*zip.File{}
	for _, f := range z.File {
		if f.Name != filepath.Base(f.Name) || !f.Mode().IsRegular() || files[f.Name] != nil {
			return empty, "", errors.New("unsafe update archive")
		}
		files[f.Name] = f
	}
	read := func(name string, limit int64) ([]byte, error) {
		f := files[name]
		if f == nil || f.UncompressedSize64 > uint64(limit) {
			return nil, errors.New("missing or oversized catalogue")
		}
		r, err := f.Open()
		if err != nil {
			return nil, err
		}
		defer r.Close()
		b, err := io.ReadAll(io.LimitReader(r, limit+1))
		if len(b) > int(limit) {
			return nil, errors.New("catalogue too large")
		}
		return b, err
	}
	raw, err := read("release.json", 1<<20)
	if err != nil {
		return empty, "", err
	}
	sig, err := read("release.json.sig", 64)
	if err != nil {
		return empty, "", err
	}
	m, err := VerifyManifest(raw, sig)
	if err != nil {
		return empty, "", err
	}
	if !Newer(m.Version, current) {
		return empty, "", errors.New("update must be newer than the installed version")
	}
	for _, a := range m.Assets {
		f := files[a.Name]
		if a.Kind != kind || a.Arch != arch || f == nil {
			continue
		}
		if f.UncompressedSize64 != uint64(a.Size) {
			return empty, "", errors.New("payload size mismatch")
		}
		r, err := f.Open()
		if err != nil {
			return empty, "", err
		}
		defer r.Close()
		p := filepath.Join(destination, "payload")
		out, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return empty, "", err
		}
		h := sha256.New()
		n, copyErr := io.Copy(io.MultiWriter(out, h), io.LimitReader(r, a.Size+1))
		syncErr := out.Sync()
		closeErr := out.Close()
		if copyErr != nil || syncErr != nil || closeErr != nil || n != a.Size || hex.EncodeToString(h.Sum(nil)) != a.SHA256 {
			_ = os.Remove(p)
			return empty, "", errors.New("update payload failed integrity check")
		}
		if kind == "linux" {
			if err := ValidateELF(p, arch); err != nil {
				_ = os.Remove(p)
				return empty, "", err
			}
		}
		return a, m.Version, nil
	}
	return empty, "", errors.New("bundle does not match this installation or processor")
}

func ValidateELF(path, arch string) error {
	f, err := elf.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	wanted := map[string]elf.Machine{"amd64": elf.EM_X86_64, "arm64": elf.EM_AARCH64}[arch]
	if wanted == elf.EM_NONE || f.Machine != wanted || f.Class != elf.ELFCLASS64 || f.Data != elf.ELFDATA2LSB || (f.Type != elf.ET_EXEC && f.Type != elf.ET_DYN) {
		return fmt.Errorf("ELF processor does not match %s", arch)
	}
	return nil
}
