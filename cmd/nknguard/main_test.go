package main

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The offline half of the CLI — init, join, invite, identity, leave — works
// in a temporary directory without root or a network.
func TestInitInviteJoinLeave(t *testing.T) {
	dir := t.TempDir()
	passwordFile := testPasswordFile(t, dir)
	flagsA := []string{"--config", filepath.Join(dir, "a.yaml"), "--state-dir", filepath.Join(dir, "a")}
	flagsB := []string{"--config", filepath.Join(dir, "b.yaml"), "--state-dir", filepath.Join(dir, "b")}
	for _, path := range []string{flagsA[1], flagsB[1]} {
		if err := os.WriteFile(path, []byte("pairing:\n  approval_required: false\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	var out, errOut bytes.Buffer
	if code := run(append(flagsA, "init", "--name", "laptop", "--dashboard-password-file", passwordFile), &out, &errOut); code != 0 {
		t.Fatalf("init: %d %s", code, errOut.String())
	}
	join := regexp.MustCompile(`nknguard join (\S+) --secret (\S+)`).FindStringSubmatch(out.String())
	if join == nil {
		t.Fatalf("init did not print a join command:\n%s", out.String())
	}

	out.Reset()
	if code := run(append(flagsA, "invite"), &out, &errOut); code != 0 || !strings.Contains(out.String(), join[1]) {
		t.Fatalf("invite: %d %q", code, out.String())
	}

	out.Reset()
	if code := run(append(flagsB, "join", join[1], "--secret", join[2], "--name", "nas"), &out, &errOut); code != 0 {
		t.Fatalf("join: %d %s", code, errOut.String())
	}
	out.Reset()
	if code := run(append(flagsB, "identity"), &out, &errOut); code != 0 || !strings.Contains(out.String(), join[1]) {
		t.Fatalf("identity after join: %q", out.String())
	}

	errOut.Reset()
	if code := run(append(flagsB, "join", join[1], "--secret", "wrong"), &out, &errOut); code == 0 {
		t.Fatal("malformed secret accepted")
	}

	out.Reset()
	if code := run(append(flagsB, "leave"), &out, &errOut); code != 0 {
		t.Fatalf("leave: %s", errOut.String())
	}
	out.Reset()
	if code := run(append(flagsB, "invite"), &out, &errOut); code == 0 {
		t.Fatal("invite worked after leave")
	}
}

func TestConfigFileHoldsNoSecret(t *testing.T) {
	dir := t.TempDir()
	passwordFile := testPasswordFile(t, dir)
	path := filepath.Join(dir, "c.yaml")
	if err := os.WriteFile(path, []byte("pairing:\n  approval_required: false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := run([]string{"--config", path, "--state-dir", filepath.Join(dir, "s"), "init", "--dashboard-password-file", passwordFile}, &out, &errOut); code != 0 {
		t.Fatal(errOut.String())
	}
	secret := regexp.MustCompile(`--secret (\S+)`).FindStringSubmatch(out.String())[1]
	out.Reset()
	_ = run([]string{"--config", path, "config"}, &out, &errOut)
	if strings.Contains(out.String(), secret) {
		t.Fatal("join secret was written to the config file")
	}
}

func TestApprovalRequiredByDefault(t *testing.T) {
	dir := t.TempDir()
	passwordFile := testPasswordFile(t, dir)
	flags := []string{"--config", filepath.Join(dir, "nas.yaml"), "--state-dir", filepath.Join(dir, "state")}
	var out, errOut bytes.Buffer
	if code := run(append(flags, "init", "--dashboard-password-file", passwordFile), &out, &errOut); code != 0 {
		t.Fatalf("init: %s", errOut.String())
	}
	if strings.Contains(out.String(), "--secret") || !strings.Contains(out.String(), "dashboard") {
		t.Fatalf("unsafe default output: %q", out.String())
	}
	out.Reset()
	errOut.Reset()
	if code := run(append(flags, "invite"), &out, &errOut); code == 0 || !strings.Contains(errOut.String(), "one-time QR") {
		t.Fatalf("legacy invite accepted: %d %s", code, errOut.String())
	}
	if code := run(append(flags, "join", "invalid", "--secret", "invalid"), &out, &errOut); code == 0 || !strings.Contains(errOut.String(), "pairing approval") {
		t.Fatalf("legacy join accepted: %d %s", code, errOut.String())
	}
}

func testPasswordFile(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "dashboard-password.txt")
	if err := os.WriteFile(path, []byte("correct horse battery staple\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDaemonCommandsWithoutDaemon(t *testing.T) {
	dir := t.TempDir()
	var out, errOut bytes.Buffer
	code := run([]string{"--socket", filepath.Join(dir, "none.sock"), "status"}, &out, &errOut)
	if code == 0 || !strings.Contains(errOut.String(), "not running") {
		t.Fatalf("status with no daemon: %d %q", code, errOut.String())
	}
}
