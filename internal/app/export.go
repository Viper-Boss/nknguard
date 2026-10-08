package app

import (
	"bytes"
	"io"
	"time"

	"github.com/Viper-Boss/nknguard/internal/config"
	"github.com/Viper-Boss/nknguard/pkg/diagnostics"
)

// ExportDiagnostics also works before connection and after a failed shutdown.
// Never walk the state directory: it contains private keys and pairing secrets.
func ExportDiagnostics(cfg config.Config, out io.Writer) error {
	var live bytes.Buffer
	if err := NewClient(cfg.Paths.Socket).Diagnostics(&live); err == nil {
		_, err = io.Copy(out, &live)
		return err
	}
	report := diagnostics.Report{GeneratedAt: time.Now()}
	report.Add("daemon", diagnostics.LevelWarn, "Offline export; live network checks were not run")
	if err := CheckShutdown(cfg.Paths.StateDir); err != nil {
		report.Add("last shutdown", diagnostics.LevelFail, err.Error())
	}
	return diagnostics.WriteBundle(out, diagnostics.BundleInput{
		Status: diagnostics.Status{Version: Version, Device: cfg.Device.Name},
		Report: report, Config: cfg.Render(),
	})
}
