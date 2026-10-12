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
// Downloads run in the background; installation still requires an explicit owner action.
func (d *Daemon) registerUpdates(mux *http.ServeMux, contexts ...context.Context) {
	var mu sync.Mutex
	var checking, installing bool
	var installStarted time.Time
	var result *releaseupdate.Result
	kind := updateKind()
	serviceCtx := context.Background()
	if len(contexts) > 0 {
		serviceCtx = contexts[0]
	}
	prefetch := newUpdatePrefetch(d, &mu, kind)
	prefetch.busy = func() bool { return installing || checking }
	prefetch.checked = func(checked releaseupdate.Result) { result = &checked }
	if len(contexts) > 0 && updateSupported(d.Config) {
		prefetch.restore()
		go prefetch.run(serviceCtx)
	}
	mux.HandleFunc("POST /api/updates/preferences", func(w http.ResponseWriter, r *http.Request) {
		if !dashboardActionAllowed(r) {
			http.Error(w, "same-origin action required", 403)
			return
		}
		var req struct {
			Enabled *bool `json:"auto_download"`
		}
		if json.NewDecoder(io.LimitReader(r.Body, 256)).Decode(&req) != nil || req.Enabled == nil {
			http.Error(w, "invalid preferences", 400)
			return
		}
		if err := prefetch.setAuto(*req.Enabled); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		writeJSON(w, map[string]bool{"auto_download": *req.Enabled})
	})
	mux.HandleFunc("POST /api/updates/download", func(w http.ResponseWriter, r *http.Request) {
		if !dashboardActionAllowed(r) {
			http.Error(w, "same-origin action required", 403)
			return
		}
		if !updateSupported(d.Config) {
			http.Error(w, "当前安装方式不支持面板更新", 400)
			return
		}
		if !prefetch.start(serviceCtx, nil) {
			http.Error(w, "update in progress", 409)
			return
		}
		w.WriteHeader(202)
		writeJSON(w, map[string]bool{"ok": true})
	})
	mux.HandleFunc("POST /api/updates/apply", func(w http.ResponseWriter, r *http.Request) {
		if !dashboardActionAllowed(r) {
			http.Error(w, "same-origin action required", 403)
			return
		}
		if !updateSupported(d.Config) {
			http.Error(w, "当前安装方式不支持面板更新", 400)
			return
		}
		mu.Lock()
		if installing || checking || prefetch.active || prefetch.download.State != "ready" || prefetch.readyDir == "" {
			mu.Unlock()
			http.Error(w, "更新尚未准备好或任务正在进行", 409)
			return
		}
		dir := prefetch.readyDir
		installing = true
		installStarted = time.Now()
		mu.Unlock()
		next, err := prefetch.validate(dir)
		if err == nil {
			err = launchUpdate(d.Config, dir)
		}
		if err != nil {
			mu.Lock()
			installing = false
			mu.Unlock()
			http.Error(w, "无法更新："+err.Error(), 400)
			return
		}
		_ = os.Remove(filepath.Join(d.Config.Paths.StateDir, "updates", "ready.json"))
		mu.Lock()
		prefetch.readyDir = ""
		prefetch.download = updateDownload{State: "installing", Version: next, Message: "更新已开始，服务将短暂重启…"}
		mu.Unlock()
		writeJSON(w, map[string]any{"ok": true, "version": next, "message": "更新已开始，请稍后刷新；配置和配对会保留。"})
	})
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
				if prefetch.download.State == "installing" {
					prefetch.download.State = "current"
					if state["state"] == "failed" {
						prefetch.download.State = "failed"
					}
					prefetch.download.Message, _ = state["message"].(string)
				}
			}
		}
		writeJSON(w, map[string]any{"current": Version, "arch": runtime.GOARCH, "kind": kind, "supported": updateSupported(d.Config), "release_url": releaseupdate.ReleaseURL, "result": result, "job": state, "download": prefetch.download, "auto_download": prefetch.auto, "installing": installing})
	})
	mux.HandleFunc("POST /api/updates/check", func(w http.ResponseWriter, r *http.Request) {
		if !dashboardActionAllowed(r) {
			http.Error(w, "same-origin action required", 403)
			return
		}
		mu.Lock()
		if checking || installing || prefetch.active {
			mu.Unlock()
			http.Error(w, "check in progress", 409)
			return
		}
		checking = true
		mu.Unlock()
		ctx, cancel := context.WithTimeout(r.Context(), 40*time.Second)
		defer cancel()
		checked, err := releaseupdate.Check(ctx, Version, kind, runtime.GOARCH)
		if err != nil {
			mu.Lock()
			checking = false
			mu.Unlock()
			http.Error(w, "无法读取 GitHub 更新信息："+err.Error(), 502)
			return
		}
		mu.Lock()
		result = &checked
		checking = false
		auto := prefetch.auto
		mu.Unlock()
		if auto && checked.Available && updateSupported(d.Config) {
			prefetch.start(serviceCtx, &checked)
		}
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
		if installing || checking || prefetch.active {
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
