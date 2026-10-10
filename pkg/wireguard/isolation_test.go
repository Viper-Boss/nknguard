package wireguard

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type absentRule struct{}

func (absentRule) Error() string { return "no rule" }
func (absentRule) ExitCode() int { return 1 }

type policyRunner struct {
	Runner
	rules      map[string]bool
	existing   bool
	insertions int
}

func (r *policyRunner) Look(string) (string, error) { return "tool", nil }
func (r *policyRunner) Run(_ context.Context, tool string, args ...string) (string, error) {
	if tool == "ip" {
		if args[1] == "delete" {
			r.existing = false
			return "", nil
		}
		if !r.existing {
			return "", errors.New("does not exist")
		}
		return "", nil
	}
	start := 4
	if args[2] == "-I" {
		start = 5
	}
	key := tool + strings.Join(args[start:], " ")
	switch args[2] {
	case "-C":
		if !r.rules[key] {
			return "", absentRule{}
		}
	case "-I":
		r.rules[key] = true
		r.insertions++
	case "-D":
		delete(r.rules, key)
	}
	return "", nil
}
func TestNASIsolationIdempotentAndRemovesOnlyOwnedRules(t *testing.T) {
	r := &policyRunner{rules: map[string]bool{"docker-unrelated": true}, existing: true}
	m := NewLinuxManagerWithRunner(nil, "nkg0", r)
	for i := 0; i < 2; i++ {
		if err := m.SetNASOnlyPolicy(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if r.insertions != 4 {
		t.Fatalf("duplicate or missing rules: %d", r.insertions)
	}
	if err := m.Down(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(r.rules) != 1 || !r.rules["docker-unrelated"] {
		t.Fatal("shutdown altered unrelated rules", r.rules)
	}
}

func TestStoppedDaemonCleanupRemovesPreviousProcessIsolation(t *testing.T) {
	r := &policyRunner{rules: map[string]bool{"docker-unrelated": true}, existing: true}
	owner := NewLinuxManagerWithRunner(nil, "nkg0", r)
	if err := owner.SetNASOnlyPolicy(context.Background()); err != nil {
		t.Fatal(err)
	}
	// A fresh cleanup process has no in-memory knowledge of the policy.
	cleanup := NewLinuxManagerWithRunner(nil, "nkg0", r)
	if err := cleanup.Down(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r.existing || len(r.rules) != 1 || !r.rules["docker-unrelated"] {
		t.Fatal("cleanup left owned resources or changed unrelated rules", r.rules)
	}
}
