package app

import (
	"bytes"
	"context"
	"log/slog"
	"sync"

	"github.com/Viper-Boss/nknguard/pkg/diagnostics"
)

// LogRing keeps the most recent log lines in memory for the diagnostics
// bundle, so a bug report has context without the daemon writing unbounded
// log files of its own. Lines are redacted on the way in.
type LogRing struct {
	mu    sync.Mutex
	lines []string
	next  int
	full  bool
}

// NewLogRing holds up to size lines.
func NewLogRing(size int) *LogRing {
	if size < 1 {
		size = 1
	}
	return &LogRing{lines: make([]string, size)}
}

// Write implements io.Writer for a slog text handler.
func (r *LogRing) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, line := range bytes.Split(bytes.TrimRight(p, "\n"), []byte("\n")) {
		value := diagnostics.Redact(string(line))
		if len(value) > 4096 {
			value = value[:4096] + "…"
		}
		r.lines[r.next] = value
		r.next = (r.next + 1) % len(r.lines)
		if r.next == 0 {
			r.full = true
		}
	}
	return len(p), nil
}

// Lines returns the buffer oldest first.
func (r *LogRing) Lines() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.full {
		return append([]string(nil), r.lines[:r.next]...)
	}
	return append(append([]string(nil), r.lines[r.next:]...), r.lines[:r.next]...)
}

// teeHandler sends every record to two handlers.
type teeHandler struct{ a, b slog.Handler }

func (t teeHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return t.a.Enabled(ctx, level) || t.b.Enabled(ctx, level)
}
func (t teeHandler) Handle(ctx context.Context, record slog.Record) error {
	if t.a.Enabled(ctx, record.Level) {
		_ = t.a.Handle(ctx, record.Clone())
	}
	if t.b.Enabled(ctx, record.Level) {
		_ = t.b.Handle(ctx, record)
	}
	return nil
}
func (t teeHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return teeHandler{t.a.WithAttrs(attrs), t.b.WithAttrs(attrs)}
}
func (t teeHandler) WithGroup(name string) slog.Handler {
	return teeHandler{t.a.WithGroup(name), t.b.WithGroup(name)}
}
