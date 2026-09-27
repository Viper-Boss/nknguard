package nknclient

import (
	"slices"
	"testing"
)

func TestSeedRPCListOrder(t *testing.T) {
	got := SeedRPCList(nil)
	want := append(append([]string(nil), ChinaSeedRPC...), OfficialSeedRPC...)
	if !slices.Equal(got, want) {
		t.Fatalf("default seeds = %q, want %q", got, want)
	}
	if len(ChinaSeedRPC) == 0 || got[0] != ChinaSeedRPC[0] {
		t.Fatalf("China seed not tried first: %q", got)
	}

	local := "http://192.168.1.10:30003"
	got = SeedRPCList([]string{" " + local + " ", "", OfficialSeedRPC[0], local})
	if got[0] != local {
		t.Fatalf("configured seed not first: %q", got)
	}
	if got[1] != OfficialSeedRPC[0] || got[2] != ChinaSeedRPC[0] {
		t.Fatalf("configured order not kept: %q", got)
	}
	if len(got) != 1+len(ChinaSeedRPC)+len(OfficialSeedRPC) {
		t.Fatalf("duplicates or blanks kept: %q", got)
	}
}
