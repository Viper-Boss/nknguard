// Package acl decides which peers may exchange traffic once they are members
// of the same network.
//
// Membership and access are separate questions. Being in a network means a
// peer's control messages are accepted; being allowed by the ACL means a
// tunnel is built and routes are installed. The default is deny, so adding a
// device to a mesh does not by itself hand it the NAS.
package acl

import (
	"fmt"
	"strings"
)

// Action is what a rule does.
type Action string

const (
	// Allow permits the pair.
	Allow Action = "allow"
	// Deny refuses it.
	Deny Action = "deny"
)

// Rule matches a source and destination. Both accept the literal "*" for any,
// a device id, a device name, or "tag:<name>" for a tag the device declares.
//
// The matcher is deliberately this small. A policy language is easy to add and
// impossible to remove, and every mesh this is aimed at is a handful of
// machines whose rules fit on one screen.
type Rule struct {
	Source      string `json:"src" yaml:"src"`
	Destination string `json:"dst" yaml:"dst"`
	Action      Action `json:"action" yaml:"action"`
}

// Policy is an ordered rule list with a default.
type Policy struct {
	Default Action `json:"default" yaml:"default"`
	Rules   []Rule `json:"rules" yaml:"rules"`
}

// DefaultPolicy denies everything. A node that fails to load its policy file
// falls back to this rather than to allow-all.
func DefaultPolicy() Policy { return Policy{Default: Deny} }

// Validate rejects a policy that would behave in a way its author did not
// write down — an unknown action, or an empty selector that silently matches
// nothing.
func (p Policy) Validate() error {
	if p.Default != Allow && p.Default != Deny {
		return fmt.Errorf("acl: default must be %q or %q, got %q", Allow, Deny, p.Default)
	}
	for index, rule := range p.Rules {
		if strings.TrimSpace(rule.Source) == "" || strings.TrimSpace(rule.Destination) == "" {
			return fmt.Errorf("acl: rule %d has an empty src or dst", index)
		}
		if rule.Action != Allow && rule.Action != Deny {
			return fmt.Errorf("acl: rule %d has unknown action %q", index, rule.Action)
		}
	}
	return nil
}

// Subject is everything the evaluator knows about one end of a pair.
type Subject struct {
	DeviceID string
	Name     string
	Tags     []string
}

func (s Subject) matches(selector string) bool {
	selector = strings.TrimSpace(selector)
	if selector == "*" {
		return true
	}
	if tag, ok := strings.CutPrefix(selector, "tag:"); ok {
		for _, owned := range s.Tags {
			if strings.EqualFold(owned, tag) {
				return true
			}
		}
		return false
	}
	return selector == s.DeviceID || strings.EqualFold(selector, s.Name)
}

// Evaluate returns the action for a pair. The first matching rule wins, which
// makes a policy readable top to bottom; an unmatched pair gets the default.
func (p Policy) Evaluate(source, destination Subject) Action {
	for _, rule := range p.Rules {
		if rule.Source == "" || rule.Destination == "" {
			continue
		}
		if source.matches(rule.Source) && destination.matches(rule.Destination) {
			return rule.Action
		}
	}
	if p.Default == Allow {
		return Allow
	}
	return Deny
}

// Permits is Evaluate reduced to a boolean, which is what call sites want.
func (p Policy) Permits(source, destination Subject) bool {
	return p.Evaluate(source, destination) == Allow
}
