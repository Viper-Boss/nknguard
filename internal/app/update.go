package app

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/Viper-Boss/nknguard/pkg/releaseupdate"
)

// registerUpdates shares the dashboard's authentication and same-origin guard.
// No timer downloads updates; only the owner's explicit actions reach GitHub.
func (d *Daemon) registerUpdates(mux *http.ServeMux) {
	var mu sync.Mutex
	var checking, installing bool
	var installStarted time.Time
	var result *releaseupdate.Result
	kind := updateKind()
	mux.HandleFunc("GET /api/updates", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		var state map[string]any
		if raw, err := os.ReadFile(filepath.Join(d.Config.Paths.StateDir, "update-result.json")); err == nil && len(raw) < 4096 {
			_ = json.Unmarshal(raw, &state)
		}
		if state != nil && installing {
			stamp, _ := state["time"].(string)
			finished, _ := time.Parse(time.RFC3339Nano, stamp)
			if finished.After(installStarted) && (state["state"] == "failed" || state["state"] == "complete") {
				installing = false
			}
		}
		writeJSON(w, map[string]any{"current": Version, "arch": runtime.GOARCH, "kind": kind, "supported": updateSupported(d.Config), "release_url": releaseupdate.ReleaseURL, "result": result, "job": state})
	})
	mux.HandleFunc("POST /api/updates/check", func(w http.ResponseWriter, r *http.Request) {
		if !dashboardActionAllowed(r) {
			http.Error(w, "same-origin action required", 403)
			return
		}
		mu.Lock()
		if checking {
			mu.Unlock()
			http.Error(w, "check in progress", 409)
			return
		}
		checking = true
		mu.Unlock()
		defer func() { mu.Lock(); checking = false; mu.Unlock() }()
		ctx, cancel := context.WithTimeout(r.Context(), 40*time.Second)
		defer cancel()
		checked, err := releaseupdate.Check(ctx, Version, kind, runtime.GOARCH)
		if err != nil {
			http.Error(w, "无法读取 GitHub 更新信息："+err.Error(), 502)
			return
		}
		mu.Lock()
		result = &checked
		mu.Unlock()
		writeJSON(w, checked)
	})
	mux.HandleFunc("POST /api/updates/upload", func(w http.ResponseWriter, r *http.Request) {
		if !dashboardActionAllowed(r) {
			http.Error(w, "same-origin action required", 403)
			return
		}
		if !updateSupported(d.Config) {
			http.Error(w, "此安装方式暂不支持面板更新，请使用安装管理器。", 400)
			return
		}
		controller := http.NewResponseController(w)
		_ = controller.SetReadDeadline(time.Now().Add(5 * time.Minute))
		_ = controller.SetWriteDeadline(time.Now().Add(5 * time.Minute))
		mu.Lock()
		if installing {
			mu.Unlock()
			http.Error(w, "update in progress", 409)
			return
		}
		installing = true
		installStarted = time.Now()
		mu.Unlock()
		launched := false
		defer func() {
			if !launched {
				mu.Lock()
				installing = false
				mu.Unlock()
			}
		}()
		root := filepath.Join(d.Config.Paths.StateDir, "updates")
		if err := os.MkdirAll(root, 0o700); err != nil {
			http.Error(w, "无法创建更新目录", 500)
			return
		}
		dir, err := os.MkdirTemp(root, "job-")
		if err != nil {
			http.Error(w, "无法创建更新任务", 500)
			return
		}
		defer func() {
			if !launched {
				_ = os.RemoveAll(dir)
			}
		}()
		file, err := os.OpenFile(filepath.Join(dir, "incoming.zip"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			http.Error(w, "无法保存更新包", 500)
			return
		}
		n, copyErr := io.Copy(file, http.MaxBytesReader(w, r.Body, releaseupdate.MaxPackageSize))
		syncErr, closeErr := file.Sync(), file.Close()
		if copyErr != nil || syncErr != nil || closeErr != nil || n == 0 {
			http.Error(w, "上传失败或更新包超过 160 MB", 400)
			return
		}
		_, next, err := releaseupdate.StageBundle(filepath.Join(dir, "incoming.zip"), dir, Version, kind, runtime.GOARCH)
		if err != nil {
			http.Error(w, "更新包验证失败："+err.Error(), 400)
			return
		}
		// The helper independently rechecks the signed archive before stopping anything.
		_ = os.Remove(filepath.Join(dir, "payload"))
		if err := launchUpdate(d.Config, dir); err != nil {
			http.Error(w, fmt.Sprintf("无法启动更新：%v", err), 500)
			return
		}
		launched = true
		writeJSON(w, map[string]any{"ok": true, "version": next, "message": "更新已开始，请稍后刷新；配置和配对会保留。"})
	})
}
