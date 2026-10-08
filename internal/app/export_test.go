package app

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Viper-Boss/nknguard/internal/config"
	"github.com/Viper-Boss/nknguard/internal/state"
)

func TestOfflineExportDoesNotReadPrivateState(t *testing.T) {
	cfg := config.Default()
	cfg.Paths.StateDir = t.TempDir()
	cfg.Paths.Socket = filepath.Join(cfg.Paths.StateDir, "missing.sock")
	private := "do-not-export-private-identity"
	if err := os.WriteFile(filepath.Join(cfg.Paths.StateDir, "identity.key"), []byte(private), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := state.New(cfg.Paths.StateDir).SaveShutdown(state.Shutdown{Error: "password=do-not-export-password", Completed: true}); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := ExportDiagnostics(cfg, &out); err != nil {
		t.Fatal(err)
	}
	gz, err := gzip.NewReader(&out)
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	archive := tar.NewReader(gz)
	count := 0
	foundFailure := false
	for {
		header, err := archive.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		raw, err := io.ReadAll(archive)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), private) || strings.Contains(string(raw), "do-not-export-password") {
			t.Fatal("private state leaked")
		}
		if header.Name == "nknguard/doctor.json" && strings.Contains(string(raw), "last shutdown") {
			foundFailure = true
		}
		count++
	}
	if count != 4 || !foundFailure {
		t.Fatalf("incomplete offline diagnostics: files=%d cleanup=%v", count, foundFailure)
	}
}
