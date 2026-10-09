// Package usagestats counts NKNGuard installations that were active in the
// last 24 hours, 30 days and 90 days, anonymously and without any server.
//
// Each installation subscribes, with fee 0, to one public NKN topic per
// window. The subscription duration IS the window: a subscription that is not
// renewed expires by itself, so the number of subscribers of a topic
// (getsubscriberscount) is the number of installations seen within it. This
// is the same scheme GenomeDock (genomedock.usage.*) and NasSimHub
// (modemdecknet*) use, with NKNGuard's own topics so the products are counted
// separately.
//
// Sizing: an installation that goes quiet keeps its subscription until its
// last renewal plus the duration, and that renewal was up to one renewal
// interval earlier. The guaranteed coverage is therefore duration minus the
// renewal interval, so every duration is its advertised span plus one day.
// NKN caps a subscription at 400 000 blocks (~92.6 days at 20 s per block).
//
// Privacy: the subscribing key is derived one-way from the device's NKN seed
// (DeriveSeed), so the public subscriber list cannot be linked to the NKN
// address the device uses for signalling. Only that public key, the topic and
// the duration are published. NKNGuard applications enforce AlwaysEnabled;
// optional switching remains available only to independent library callers.
package usagestats

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Window is one statistics window: a topic whose subscription duration
// defines what its subscriber count means.
type Window struct {
	// Key names the window in API responses: day, month, quarter.
	Key string
	// Topic is the public on-chain topic. Each window needs its own, because
	// one key holds a single subscription (and expiry) per topic.
	Topic string
	// Blocks is the subscription duration: the advertised span plus one
	// renewal interval, at 20 s per block.
	Blocks int
	// Span is the coverage the count is advertised as.
	Span time.Duration
}

// RenewInterval is how often each window's subscription is pushed out.
const RenewInterval = 24 * time.Hour

// Windows are NKNGuard's topics. Do not reuse another product's topics: each
// product counts its own installations.
var Windows = []Window{
	{Key: "day", Topic: "nknguard.usage.24h", Blocks: 8640, Span: 24 * time.Hour},            // 2 days
	{Key: "month", Topic: "nknguard.usage.30d", Blocks: 133920, Span: 30 * 24 * time.Hour},   // 31 days
	{Key: "quarter", Topic: "nknguard.usage.90d", Blocks: 393120, Span: 90 * 24 * time.Hour}, // 91 days
}

const (
	// BlockTime is NKN's target block interval.
	BlockTime = 20 * time.Second
	// MaxBlocks is NKN's maximum subscription duration.
	MaxBlocks = 400000
	// checkEvery is how often the reporter looks for a due window.
	checkEvery = time.Hour
	// retryAfter is the wait after a failed check-in.
	retryAfter = 5 * time.Minute
	// countsTTL is how long counts are cached.
	countsTTL = 10 * time.Minute
	// minRefresh bounds forced count refreshes.
	minRefresh = 5 * time.Second
)

// DeriveSeed returns the 32-byte seed of the statistics key. It is derived
// one-way from the device's NKN seed, so it needs no storage of its own and
// cannot be linked back to the device's NKN address.
func DeriveSeed(nknSeed []byte) []byte {
	mac := hmac.New(sha256.New, []byte("nknguard usage-stats v1"))
	mac.Write(nknSeed)
	return mac.Sum(nil)
}

// Chain is what the reporter needs from the NKN blockchain.
type Chain interface {
	// Subscribe subscribes the statistics key to topic for blocks and
	// returns once the subscription is written to a block.
	Subscribe(ctx context.Context, topic string, blocks int) error
	// Unsubscribe removes the statistics key from topic.
	Unsubscribe(ctx context.Context, topic string) error
	// Count returns the number of subscribers of topic.
	Count(ctx context.Context, topic string) (int, error)
	// Address is the public subscriber name of the statistics key.
	Address() string
}

// ErrUnavailable is returned when this build has no NKN support.
var ErrUnavailable = errors.New("usage statistics need a build with NKN support")

// Counts holds the subscriber count of each window. A nil value means the
// query failed; it never means zero.
type Counts struct {
	Day       *int      `json:"day"`
	Month     *int      `json:"month"`
	Quarter   *int      `json:"quarter"`
	FetchedAt time.Time `json:"fetched_at,omitempty"`
	Error     string    `json:"error,omitempty"`
}

// Status is what user interfaces show.
type Status struct {
	Enabled     bool      `json:"enabled"`
	Counts      Counts    `json:"counts"`
	LastCheckIn time.Time `json:"last_check_in,omitempty"`
	LastError   string    `json:"last_error,omitempty"`
	Address     string    `json:"address,omitempty"`
}

type fileState struct {
	// Enabled is the user's choice; nil means the default applies.
	Enabled *bool                `json:"enabled,omitempty"`
	Renewed map[string]time.Time `json:"renewed,omitempty"`
}

// Reporter checks in once per window per day while enabled and reads counts.
type Reporter struct {
	// Chain is nil in builds without NKN support.
	Chain Chain
	// Path is the JSON file holding the switch and the last check-ins. It
	// holds no secrets.
	Path string
	// DefaultEnabled applies until the user has chosen.
	DefaultEnabled bool
	// AlwaysEnabled is the application policy; persisted legacy switches
	// cannot override it. Library callers may still use optional reporting.
	AlwaysEnabled bool
	Logger        *slog.Logger
	// Now is for tests.
	Now func() time.Time

	once     sync.Once
	mu       sync.Mutex
	state    fileState
	lastErr  string
	counts   Counts
	countsAt time.Time
	wake     chan struct{}
	countMu  sync.Mutex
}

func (r *Reporter) init() {
	r.once.Do(func() {
		if r.Now == nil {
			r.Now = time.Now
		}
		if r.Logger == nil {
			r.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
		}
		r.wake = make(chan struct{}, 1)
		r.state = r.load()
	})
}

func (r *Reporter) load() fileState {
	state := fileState{Renewed: map[string]time.Time{}}
	if r.Path == "" {
		return state
	}
	raw, err := os.ReadFile(r.Path)
	if err != nil {
		return state
	}
	if json.Unmarshal(raw, &state) != nil {
		return fileState{Renewed: map[string]time.Time{}}
	}
	if state.Renewed == nil {
		state.Renewed = map[string]time.Time{}
	}
	return state
}

// refresh re-reads the file; the caller holds r.mu. More than one process
// may share the file (the Windows window and its background service), so
// every decision and every write starts from what is on disk: a choice made
// in one process is never overwritten by another's stale copy.
func (r *Reporter) refresh() {
	if r.Path != "" {
		r.state = r.load()
	}
}

// save writes the state; the caller holds r.mu.
func (r *Reporter) save() error {
	if r.Path == "" {
		return nil
	}
	raw, err := json.MarshalIndent(r.state, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(r.Path), 0o700); err != nil {
		return err
	}
	tmp := r.Path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, r.Path)
}

// Enabled reports whether statistics are on.
func (r *Reporter) Enabled() bool {
	r.init()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.refresh()
	return r.enabledLocked()
}

func (r *Reporter) enabledLocked() bool {
	if r.AlwaysEnabled {
		return true
	}
	if r.state.Enabled != nil {
		return *r.state.Enabled
	}
	return r.DefaultEnabled
}

// SetEnabled records the user's choice. Turning statistics off removes this
// installation from every topic (best effort; an unsubscribe that fails
// leaves a subscription that simply expires) and stops all transactions.
func (r *Reporter) SetEnabled(ctx context.Context, enabled bool) error {
	if r.AlwaysEnabled && !enabled {
		return errors.New("匿名使用人数统计自动启用，不提供关闭开关")
	}
	r.init()
	r.mu.Lock()
	r.refresh()
	r.state.Enabled = &enabled
	if !enabled {
		r.state.Renewed = map[string]time.Time{}
		r.lastErr = ""
	}
	err := r.save()
	r.mu.Unlock()
	if err != nil {
		return err
	}
	if enabled {
		select {
		case r.wake <- struct{}{}:
		default:
		}
		return nil
	}
	if r.Chain != nil {
		for _, window := range Windows {
			if err := r.Chain.Unsubscribe(ctx, window.Topic); err != nil {
				r.Logger.Info("usage statistics: unsubscribe failed; the subscription will expire", "component", "usage", "topic", window.Topic, "error", err)
			}
		}
	}
	return nil
}

// Run checks in while enabled until ctx ends.
func (r *Reporter) Run(ctx context.Context) {
	r.init()
	if r.Chain == nil {
		return
	}
	for {
		wait := checkEvery
		if r.Enabled() {
			if !r.checkIn(ctx) {
				wait = retryAfter
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-r.wake:
		case <-time.After(wait):
		}
	}
}

// due lists the windows whose last check-in is older than RenewInterval.
func (r *Reporter) due() []Window {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.refresh()
	now := r.Now()
	var out []Window
	for _, window := range Windows {
		last, ok := r.state.Renewed[window.Topic]
		if !ok || now.Sub(last) >= RenewInterval || last.After(now) {
			out = append(out, window)
		}
	}
	return out
}

// checkIn renews every due window and reports whether all succeeded.
func (r *Reporter) checkIn(ctx context.Context) bool {
	r.init()
	windows := r.due()
	var failures []string
	for _, window := range windows {
		if !r.Enabled() || ctx.Err() != nil {
			return true
		}
		if err := r.Chain.Subscribe(ctx, window.Topic, window.Blocks); err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", window.Topic, err))
			continue
		}
		r.mu.Lock()
		r.refresh()
		if r.enabledLocked() {
			r.state.Renewed[window.Topic] = r.Now()
			if err := r.save(); err != nil {
				r.Logger.Warn("usage statistics: cannot save state", "component", "usage", "error", err)
			}
		}
		r.mu.Unlock()
		r.Logger.Info("usage statistics: checked in", "component", "usage", "topic", window.Topic)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(failures) > 0 {
		r.lastErr = strings.Join(failures, "; ")
		r.Logger.Info("usage statistics: check-in failed; will retry", "component", "usage", "error", r.lastErr)
		return false
	}
	if len(windows) > 0 {
		r.lastErr = ""
		r.countsAt = time.Time{} // show the new check-in on the next read
	}
	return true
}

// Counts returns the cached counts, refreshing them when older than ten
// minutes or when force is set (at most every five seconds).
func (r *Reporter) Counts(ctx context.Context, force bool) Counts {
	r.init()
	r.countMu.Lock()
	defer r.countMu.Unlock()
	r.mu.Lock()
	fetched := !r.countsAt.IsZero()
	age := r.Now().Sub(r.countsAt)
	cached := r.counts
	r.mu.Unlock()
	if fetched && ((age < countsTTL && !force) || age < minRefresh) {
		return cached
	}
	var counts Counts
	if r.Chain == nil {
		counts.Error = ErrUnavailable.Error()
	} else {
		var failures []string
		for _, window := range Windows {
			n, err := r.Chain.Count(ctx, window.Topic)
			if err != nil {
				failures = append(failures, fmt.Sprintf("%s: %v", window.Topic, err))
				continue
			}
			value := n
			switch window.Key {
			case "day":
				counts.Day = &value
			case "month":
				counts.Month = &value
			case "quarter":
				counts.Quarter = &value
			}
		}
		counts.Error = strings.Join(failures, "; ")
	}
	counts.FetchedAt = r.Now()
	r.mu.Lock()
	r.counts = counts
	r.countsAt = counts.FetchedAt
	if missing(counts) == len(Windows) {
		// Nothing answered: try again on the next read instead of caching
		// an empty result for ten minutes.
		r.countsAt = time.Time{}
	}
	r.mu.Unlock()
	return counts
}

func missing(c Counts) int {
	n := 0
	for _, v := range []*int{c.Day, c.Month, c.Quarter} {
		if v == nil {
			n++
		}
	}
	return n
}

// Status returns the switch, the counts and the last check-in.
func (r *Reporter) Status(ctx context.Context, force bool) Status {
	counts := r.Counts(ctx, force)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.refresh()
	status := Status{Enabled: r.enabledLocked(), Counts: counts, LastError: r.lastErr}
	for _, last := range r.state.Renewed {
		if last.After(status.LastCheckIn) {
			status.LastCheckIn = last
		}
	}
	if r.Chain != nil {
		status.Address = r.Chain.Address()
	}
	return status
}
