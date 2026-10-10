package releaseupdate

import (
	"archive/zip"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

// Signed harmless fixture: its kind cannot be selected by the NAS updater.
const fixtureManifest = `{"version":"v0.2.16-test.1","assets":[{"name":"fixture.txt","kind":"fixture","arch":"test","size":20,"sha256":"f529ab4c4f307e820dc9260faeb4732f94c52f9e292cf050b5cd0030c236cd2e"}]}`
const fixtureSignature = "jgt62uQ9IRmlbqTcIqyX6/nbc85pwPcmguFPt3gZakxWGP7WjNfbtwuhmy4RJg3+90YX+zJTeBTo+Sek40b3Cg=="

func TestSignedBundleValidation(t *testing.T) {
	for _, mutation := range []string{"valid", "payload", "signature", "path", "symlink", "extra", "architecture", "downgrade"} {
		t.Run(mutation, func(t *testing.T) {
			root := t.TempDir()
			sig, _ := base64.StdEncoding.DecodeString(fixtureSignature)
			if mutation == "signature" {
				sig[0] ^= 1
			}
			payload := []byte("update-test-fixture\n")
			if mutation == "payload" {
				payload[0] ^= 1
			}
			archive := filepath.Join(root, "bundle.zip")
			f, err := os.Create(archive)
			if err != nil {
				t.Fatal(err)
			}
			z := zip.NewWriter(f)
			for _, item := range []struct {
				name string
				body []byte
			}{{"release.json", []byte(fixtureManifest)}, {"release.json.sig", sig}, {"fixture.txt", payload}} {
				h := &zip.FileHeader{Name: item.name, Method: zip.Deflate}
				h.SetMode(0o600)
				if item.name == "fixture.txt" && mutation == "path" {
					h.Name = "../fixture.txt"
				}
				if item.name == "fixture.txt" && mutation == "symlink" {
					h.SetMode(os.ModeSymlink | 0o600)
				}
				w, err := z.CreateHeader(h)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := w.Write(item.body); err != nil {
					t.Fatal(err)
				}
			}
			if mutation == "extra" {
				_, _ = z.Create("extra.txt")
			}
			if err := z.Close(); err != nil {
				t.Fatal(err)
			}
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
			destination := filepath.Join(root, "stage")
			if err := os.Mkdir(destination, 0o700); err != nil {
				t.Fatal(err)
			}
			current, arch := "0.2.15-preview.1", "test"
			if mutation == "architecture" {
				arch = "arm64"
			}
			if mutation == "downgrade" {
				current = "0.2.17"
			}
			_, _, err = StageBundle(archive, destination, current, "fixture", arch)
			if mutation == "valid" && err != nil {
				t.Fatal(err)
			}
			if mutation != "valid" && err == nil {
				t.Fatal("unsafe bundle accepted")
			}
			if _, err := os.Stat(filepath.Join(root, "fixture.txt")); err == nil {
				t.Fatal("archive escaped staging")
			}
		})
	}
}
