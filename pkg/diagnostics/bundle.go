package diagnostics

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
)

// secretPatterns are the shapes a secret takes in this program. The redactor
// runs over every byte that enters a bundle, including log lines it did not
// generate, because the expensive failure here is silent.
var secretPatterns = []*regexp.Regexp{
	// WireGuard keys: 44 characters of base64 ending in '='.
	regexp.MustCompile(`\b[A-Za-z0-9+/]{43}=`),
	// Anything that announces itself.
	regexp.MustCompile(`(?i)\b(private[_-]?key|privatekey|join[_-]?secret|joinsecret|wallet[_-]?seed|seed|secret|password|passphrase|token|authorization)\b\s*[:=]\s*\S+`),
	// Hex blobs long enough to be key material.
	regexp.MustCompile(`\b[0-9a-fA-F]{64,}\b`),
}

// Redact replaces anything that looks like key material.
func Redact(text string) string {
	for _, pattern := range secretPatterns {
		text = pattern.ReplaceAllStringFunc(text, func(match string) string {
			if index := strings.IndexAny(match, ":="); index >= 0 {
				return match[:index+1] + " [redacted]"
			}
			return "[redacted]"
		})
	}
	return text
}

// BundleInput is what goes into an export.
type BundleInput struct {
	Status Status
	Report Report
	// Config is the rendered configuration file. It contains no secrets by
	// design, and is redacted anyway.
	Config string
	// Logs are recent log lines, newest last.
	Logs []string
}

// WriteBundle writes a gzipped tar of the diagnostics.
//
// Every member is passed through Redact on the way in — not on the way out,
// not optionally. If a future field carries something sensitive, the bundle
// still will not.
func WriteBundle(out io.Writer, input BundleInput) error {
	gz := gzip.NewWriter(out)
	defer func() { _ = gz.Close() }()
	archive := tar.NewWriter(gz)
	defer func() { _ = archive.Close() }()

	now := time.Now()
	status, err := json.MarshalIndent(input.Status, "", "  ")
	if err != nil {
		return fmt.Errorf("diagnostics: encode status: %w", err)
	}
	report, err := json.MarshalIndent(input.Report, "", "  ")
	if err != nil {
		return fmt.Errorf("diagnostics: encode report: %w", err)
	}
	members := []struct {
		name string
		body string
	}{
		{"nknguard/status.json", string(status)},
		{"nknguard/doctor.json", string(report)},
		{"nknguard/config.yaml", input.Config},
		{"nknguard/log.txt", strings.Join(input.Logs, "\n")},
	}
	for _, member := range members {
		body := Redact(member.body)
		header := &tar.Header{
			Name:    member.name,
			Mode:    0o600,
			Size:    int64(len(body)),
			ModTime: now,
		}
		if err := archive.WriteHeader(header); err != nil {
			return fmt.Errorf("diagnostics: write header %s: %w", member.name, err)
		}
		if _, err := io.WriteString(archive, body); err != nil {
			return fmt.Errorf("diagnostics: write %s: %w", member.name, err)
		}
	}
	if err := archive.Close(); err != nil {
		return fmt.Errorf("diagnostics: close archive: %w", err)
	}
	return gz.Close()
}
