//go:build windows

package main

import (
	"image/color"
	"testing"
)

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
