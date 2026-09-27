package wireguard

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// CommandTimeout bounds every external command. `ip` and `wg` are fast or
// broken; a call that has not returned in ten seconds is not going to.
const CommandTimeout = 10 * time.Second

// Runner is how this package reaches `wg` and `ip`.
//
// It is an interface for one reason that matters more than testability: every
// call site passes an argument slice, never a shell string. There is no code
// path in NKNGuard that hands user input to a shell, and the type system is
// what keeps it that way.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) (string, error)
	RunStdin(ctx context.Context, input string, name string, args ...string) (string, error)
	Look(name string) (string, error)
}

// ExecRunner is the real implementation.
type ExecRunner struct{}

// Run executes a command and returns its combined output.
func (ExecRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, CommandTimeout)
	defer cancel()
	var stdout, stderr bytes.Buffer
	command := exec.CommandContext(ctx, name, args...)
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return stdout.String(), fmt.Errorf("wireguard: %s %s: %w: %s", name, strings.Join(args, " "), err, firstLine(stderr.String()))
	}
	return stdout.String(), nil
}

// RunStdin executes a command with input on its standard input. It is how a
// generated configuration reaches `wg setconf` without ever being written to a
// file that another process could read.
func (ExecRunner) RunStdin(ctx context.Context, input string, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, CommandTimeout)
	defer cancel()
	var stdout, stderr bytes.Buffer
	command := exec.CommandContext(ctx, name, args...)
	command.Stdin = strings.NewReader(input)
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return stdout.String(), fmt.Errorf("wireguard: %s %s: %w: %s", name, strings.Join(args, " "), err, firstLine(stderr.String()))
	}
	return stdout.String(), nil
}

// Look resolves a binary on PATH.
func (ExecRunner) Look(name string) (string, error) { return exec.LookPath(name) }

func firstLine(text string) string {
	text = strings.TrimSpace(text)
	if index := strings.IndexByte(text, '\n'); index >= 0 {
		return strings.TrimSpace(text[:index])
	}
	return text
}
