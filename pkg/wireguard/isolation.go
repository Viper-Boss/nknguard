package wireguard

import (
	"context"
	"errors"
	"fmt"
)

func (m *LinuxManager) isolationRule(direction string) []string {
	return []string{direction, m.ifaceName, "-m", "comment", "--comment", "nknguard:" + m.ifaceName + ":nas-only", "-j", "DROP"}
}

// SetNASOnlyPolicy blocks forwarding in both directions on this interface.
// INPUT/OUTPUT remain untouched, so NAS services are reachable. Rules are
// inserted before Docker ACCEPT rules; neither global forwarding nor other
// programs' firewall rules are changed.
func (m *LinuxManager) SetNASOnlyPolicy(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, tool := range []string{"iptables", "ip6tables"} {
		if _, err := m.runner.Look(tool); err != nil {
			return fmt.Errorf("NAS isolation requires %s: %w", tool, err)
		}
	}
	m.isolated = true // retain protection if later setup fails until Down succeeds.
	for _, tool := range []string{"iptables", "ip6tables"} {
		for _, direction := range []string{"-i", "-o"} {
			rule := m.isolationRule(direction)
			if _, err := m.runner.Run(ctx, tool, append([]string{"-w", "3", "-C", "FORWARD"}, rule...)...); err == nil {
				continue
			}
			if _, err := m.runner.Run(ctx, tool, append([]string{"-w", "3", "-I", "FORWARD", "1"}, rule...)...); err != nil {
				return fmt.Errorf("install NAS isolation: %w", err)
			}
		}
	}
	return nil
}

func (m *LinuxManager) clearIsolationLocked(ctx context.Context) error {
	var result error
	for _, tool := range []string{"iptables", "ip6tables"} {
		// A cleanup command has a new manager, but rules from a stopped or
		// killed daemon still belong to this interface. Check exact ownership
		// instead of relying on process-local state. Ordinary clients may not
		// have firewall tools when no isolation policy was installed.
		if _, err := m.runner.Look(tool); err != nil {
			if m.isolated {
				result = errors.Join(result, err)
			}
			continue
		}
		for _, direction := range []string{"-i", "-o"} {
			rule := m.isolationRule(direction)
			if _, err := m.runner.Run(ctx, tool, append([]string{"-w", "3", "-C", "FORWARD"}, rule...)...); err != nil {
				var exit interface{ ExitCode() int }
				if !errors.As(err, &exit) || exit.ExitCode() != 1 {
					result = errors.Join(result, err)
				}
				continue
			}
			_, err := m.runner.Run(ctx, tool, append([]string{"-w", "3", "-D", "FORWARD"}, rule...)...)
			result = errors.Join(result, err)
		}
	}
	if result == nil {
		m.isolated = false
	}
	return result
}
