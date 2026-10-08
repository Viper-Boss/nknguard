//go:build windows

package main

import (
	"github.com/Viper-Boss/nknguard/internal/state"
	"image/color"
	"path/filepath"
	"testing"
)

func TestReopenedClientShowsIncompleteCleanup(t *testing.T) {
	dir := t.TempDir()
	store := state.New(dir)
	if err := store.SaveShutdown(state.Shutdown{Completed: true, Error: "uninstall failed"}); err != nil {
		t.Fatal(err)
	}
	w := &clientWindow{globals: globals{stateDir: dir, socket: filepath.Join(dir, "missing.sock"), configPath: filepath.Join(dir, "missing.yaml")}}
	view := w.snapshot()
	if !stateFlag(view, "cleanup_failed") || stateText(view, "error") != "uninstall failed" {
		t.Fatalf("cleanup failure hidden: %v", view)
	}
	if err := store.SaveShutdown(state.Shutdown{Completed: true}); err != nil {
		t.Fatal(err)
	}
	if stateFlag(w.snapshot(), "cleanup_failed") {
		t.Fatal("successful retry still marked as failed")
	}
}

func TestAppIcon(t *testing.T) {
	img := appIconImage(64)
	if b := img.Bounds(); b.Dx() != 64 || b.Dy() != 64 {
		t.Fatalf("icon size %v", b)
	}
	// Rounded corners are transparent, the diagonal stroke of the N is white.
	if _, _, _, a := img.At(0, 0).RGBA(); a != 0 {
		t.Fatal("corner is not transparent")
	}
	if c := color.RGBAModel.Convert(img.At(32, 32)).(color.RGBA); c != (color.RGBA{0xff, 0xff, 0xff, 0xff}) {
		t.Fatalf("centre pixel %v, want the white stroke", c)
	}
}

func TestStateHelpers(t *testing.T) {
	state := map[string]any{"paired": true, "path": "nkn-relay", "virtual_ip": ""}
	if !stateFlag(state, "paired") || stateFlag(state, "connected") {
		t.Fatal("flags")
	}
	if pathText(stateText(state, "path")) != "NKN 加密中继" || pathText("") != "正在寻找链路" {
		t.Fatal("path text")
	}
	if orDash(stateText(state, "virtual_ip")) != "—" || orDefault("x", "y") != "x" {
		t.Fatal("defaults")
	}
}

func TestNASURLRejectsUntrustedTargets(t *testing.T) {
	for _, value := range []string{"", "—", "javascript:alert(1)", "127.0.0.1", "0.0.0.0", "224.0.0.1", "10.88.0.1/evil"} {
		if target, err := nasWebURL(value); err == nil {
			t.Fatalf("accepted %q as %s", value, target)
		}
	}
	for value, want := range map[string]string{"10.88.0.1": "http://10.88.0.1:5666/", "fd00::1": "http://[fd00::1]:5666/"} {
		if got, err := nasWebURL(value); err != nil || got != want {
			t.Fatalf("target %s: %s %v", value, got, err)
		}
	}
}
