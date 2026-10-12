package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	random "math/rand/v2"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/Viper-Boss/nknguard/pkg/releaseupdate"
)

type updateDownload struct {
	State   string `json:"state"`
	Version string `json:"version,omitempty"`
	Bytes   int64  `json:"bytes"`
	Total   int64  `json:"total"`
	Message string `json:"message"`
}
type updatePrefetch struct {
	mu       *sync.Mutex
	d        *Daemon
	kind     string
	auto     bool
	active   bool
	readyDir string
	download updateDownload
	busy     func() bool                // called with mu held
	checked  func(releaseupdate.Result) // called with mu held
	check    func(context.Context, string, string, string) (releaseupdate.Result, error)
	fetch    func(context.Context, string, string, func(int64, int64)) error
	stage    func(string, string, string, string, string) (releaseupdate.Asset, string, error)
}

func newUpdatePrefetch(d *Daemon, mu *sync.Mutex, kind string) *updatePrefetch {
	u := &updatePrefetch{d: d, mu: mu, kind: kind, auto: true, check: releaseupdate.Check, stage: releaseupdate.StageBundle, download: updateDownload{State: "idle", Message: "后台检查正式版，下载完成后可一键更新。"}}
	u.fetch = func(ctx context.Context, url, path string, progress func(int64, int64)) error {
		return releaseupdate.DownloadBundle(ctx, nil, url, path, progress)
	}
	if d.Config.Paths.StateDir != "" {
		var prefs struct {
			Auto bool `json:"auto_download"`
		}
		if raw, err := os.ReadFile(filepath.Join(d.Config.Paths.StateDir, "update-preferences.json")); err == nil && json.Unmarshal(raw, &prefs) == nil {
			u.auto = prefs.Auto
		}
	}
	return u
}

func (u *updatePrefetch) start(ctx context.Context, result *releaseupdate.Result) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.active || (u.busy != nil && u.busy()) {
		return false
	}
	u.active = true
	u.download = updateDownload{State: "checking", Message: "正在检查正式发布版本…"}
	go u.prepare(ctx, result)
	return true
}

func (u *updatePrefetch) prepare(ctx context.Context, result *releaseupdate.Result) {
	var err error
	var dir string
	defer func() {
		if err != nil && dir != "" {
			_ = os.RemoveAll(dir)
		}
		u.mu.Lock()
		u.active = false
		if err != nil {
			u.download = updateDownload{State: "failed", Message: "下载暂未完成，可重试：" + err.Error()}
		}
		u.mu.Unlock()
	}()
	ctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	var checked releaseupdate.Result
	if result != nil {
		checked = *result
	} else {
		checkCtx, stop := context.WithTimeout(ctx, 40*time.Second)
		checked, err = u.check(checkCtx, Version, u.kind, runtime.GOARCH)
		stop()
		if err != nil {
			return
		}
	}
	u.mu.Lock()
	if u.checked != nil {
		u.checked(checked)
	}
	u.mu.Unlock()
	if !checked.Available {
		u.mu.Lock()
		u.download = updateDownload{State: "current", Message: "当前已是最新正式发布版本。"}
		u.mu.Unlock()
		return
	}
	if checked.Asset == nil || checked.BundleURL == "" {
		err = errors.New("发布中没有匹配本机的签名更新包")
		return
	}
	// A ready marker is never trusted without revalidating the actual archive.
	root := filepath.Join(u.d.Config.Paths.StateDir, "updates")
	if err = os.MkdirAll(root, 0o700); err != nil {
		return
	}
	u.mu.Lock()
	old := u.readyDir
	u.mu.Unlock()
	if old != "" {
		if next, e := u.validate(old); e == nil && next == checked.Latest {
			u.mu.Lock()
			u.download = updateDownload{State: "ready", Version: next, Message: "更新已下载并验证，可以立即更新。"}
			u.mu.Unlock()
			return
		}
	}
	dir, err = os.MkdirTemp(root, "job-prefetch-")
	if err != nil {
		return
	}
	u.mu.Lock()
	u.download = updateDownload{State: "downloading", Version: checked.Latest, Message: "正在后台下载更新包…"}
	u.mu.Unlock()
	err = u.fetch(ctx, checked.BundleURL, filepath.Join(dir, "incoming.zip"), func(n, total int64) { u.mu.Lock(); u.download.Bytes = n; u.download.Total = total; u.mu.Unlock() })
	if err != nil {
		return
	}
	u.mu.Lock()
	u.download.State = "verifying"
	u.download.Message = "正在验证发布签名和安装包…"
	u.mu.Unlock()
	var next string
	next, err = u.validate(dir)
	if err != nil {
		return
	}
	if next != checked.Latest {
		err = errors.New("下载包版本与发布目录不一致")
		return
	}
	if err = atomicUpdateJSON(filepath.Join(root, "ready.json"), map[string]string{"job": filepath.Base(dir), "version": next}); err != nil {
		return
	}
	u.mu.Lock()
	u.readyDir = dir
	u.download = updateDownload{State: "ready", Version: next, Message: "更新已下载并验证，可以立即更新。"}
	u.mu.Unlock()
	if old != "" && old != dir {
		_ = os.RemoveAll(old)
	}
}

func (u *updatePrefetch) validate(dir string) (string, error) {
	staged, err := os.MkdirTemp(dir, "verify-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(staged)
	_, next, err := u.stage(filepath.Join(dir, "incoming.zip"), staged, Version, u.kind, runtime.GOARCH)
	return next, err
}

func atomicUpdateJSON(path string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".update-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_ = f.Chmod(0o600)
	_, err = f.Write(raw)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

func (u *updatePrefetch) restore() {
	root := filepath.Join(u.d.Config.Paths.StateDir, "updates")
	var marker struct{ Job, Version string }
	raw, err := os.ReadFile(filepath.Join(root, "ready.json"))
	valid := err == nil && len(raw) < 4096 && json.Unmarshal(raw, &marker) == nil && marker.Job == filepath.Base(marker.Job) && strings.HasPrefix(marker.Job, "job-prefetch-")
	if valid {
		dir := filepath.Join(root, marker.Job)
		if next, err := u.validate(dir); err == nil && next == marker.Version {
			u.mu.Lock()
			u.readyDir = dir
			u.download = updateDownload{State: "ready", Version: next, Message: "更新已下载并验证，可以立即更新。"}
			u.mu.Unlock()
		} else {
			_ = os.Remove(filepath.Join(root, "ready.json"))
		}
	}
	// Reclaim incomplete downloads after a restart, keeping at most one ready package.
	entries, _ := os.ReadDir(root)
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), "job-prefetch-") && filepath.Join(root, e.Name()) != u.readyDir {
			_ = os.RemoveAll(filepath.Join(root, e.Name()))
		}
	}
}

func (u *updatePrefetch) run(ctx context.Context) {
	timer := time.NewTimer(time.Minute + time.Duration(random.IntN(30000))*time.Millisecond)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		u.mu.Lock()
		enabled := u.auto
		u.mu.Unlock()
		if enabled {
			u.start(ctx, nil)
			for {
				u.mu.Lock()
				active := u.active
				u.mu.Unlock()
				if !active {
					break
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(time.Second):
				}
			}
		}
		interval := 6 * time.Hour
		u.mu.Lock()
		failed := u.download.State == "failed"
		u.mu.Unlock()
		if failed {
			interval = 30 * time.Minute
		}
		timer.Reset(interval + time.Duration(random.Int64N(int64(interval/10))))
	}
}

func (u *updatePrefetch) setAuto(enabled bool) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if err := atomicUpdateJSON(filepath.Join(u.d.Config.Paths.StateDir, "update-preferences.json"), map[string]bool{"auto_download": enabled}); err != nil {
		return fmt.Errorf("保存自动下载设置：%w", err)
	}
	u.auto = enabled
	return nil
}
