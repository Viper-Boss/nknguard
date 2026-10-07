//go:build windows

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows"

	"github.com/Viper-Boss/nknguard/internal/app"
	"github.com/Viper-Boss/nknguard/internal/state"
	"github.com/Viper-Boss/nknguard/pkg/mesh"
	"github.com/Viper-Boss/nknguard/pkg/usagestats"
)

type clientWindow struct {
	mu            sync.Mutex
	globals       globals
	pairing       bool
	connecting    bool
	disconnecting bool
	launchDone    chan struct{}
	background    windows.Handle
	connectSince  time.Time
	message       string
	pairCode      string
	nasAddress    string
	errorMessage  string
	// usage is the anonymous usage-statistics reporter; nil if unavailable.
	usage *usagestats.Reporter
}

func (w *clientWindow) update(fn func()) {
	w.mu.Lock()
	defer w.mu.Unlock()
	fn()
}

func (w *clientWindow) snapshot() map[string]any {
	w.mu.Lock()
	pairing, connecting, connectSince, message, pairCode, nasAddress, errorMessage :=
		w.pairing, w.connecting, w.connectSince, w.message, w.pairCode, w.nasAddress, w.errorMessage
	disconnecting := w.disconnecting
	w.mu.Unlock()
	cfg, _, err := loadConfig(w.globals)
	result := map[string]any{
		"paired": false, "connected": false, "pairing": pairing,
		"connecting": connecting, "message": message,
		"disconnecting": disconnecting,
		"pair_code":     pairCode, "nas_address": nasAddress,
		"error": errorMessage, "path": "none",
	}
	if err != nil {
		result["error"] = err.Error()
		return result
	}
	current, err := state.New(cfg.Paths.StateDir).LoadMembership()
	if err == nil && current.NetworkID != "" {
		result["paired"] = true
		result["device_id"] = current.DeviceID
		result["network_id"] = current.NetworkID
		if len(cfg.Discovery.StaticPeers) > 0 {
			result["nas_address"] = cfg.Discovery.StaticPeers[0]
		}
	}
	status, err := app.NewClient(cfg.Paths.Socket).Status()
	if err == nil {
		w.update(func() { w.connecting = false })
		result["connected"] = true
		result["connecting"] = false
		result["local_nkn_address"] = status.NKNAddress
		result["virtual_ip"] = status.VirtualIP
		result["wireguard_state"] = status.WireGuard.State
		for _, peer := range status.Peers {
			if peer.Path == mesh.PathDirectWG || peer.Path == mesh.PathNKNRelay {
				result["path"] = peer.Path
				result["nas_address"] = peer.NKNAddress
				result["nas_ip"] = peer.VirtualIP
				break
			}
		}
	} else if connecting {
		errorPath := filepath.Join(os.Getenv("LOCALAPPDATA"), "NKNGuard", "last-error.txt")
		if raw, readErr := os.ReadFile(errorPath); readErr == nil && len(raw) > 0 {
			w.update(func() { w.connecting = false; w.errorMessage = strings.TrimSpace(string(raw)) })
			result["connecting"] = false
			result["error"] = strings.TrimSpace(string(raw))
		} else if time.Since(connectSince) > 45*time.Second {
			message := "连接超时；请确认已安装 WireGuard，并检查 Windows 管理员授权"
			w.update(func() { w.connecting = false; w.errorMessage = message })
			result["connecting"] = false
			result["error"] = message
		}
	}
	return result
}

type pairProgress struct{ window *clientWindow }

var codePattern = regexp.MustCompile("验证码 ([0-9]{6})")

func (p pairProgress) Write(raw []byte) (int, error) {
	message := strings.TrimSpace(string(raw))
	p.window.update(func() {
		p.window.message = message
		if matched := codePattern.FindStringSubmatch(message); len(matched) == 2 {
			p.window.pairCode = matched[1]
		}
	})
	return len(raw), nil
}

func (w *clientWindow) pair(invitation, name string) error {
	invite, err := app.ParsePairInvite(invitation)
	if err != nil {
		return err
	}
	cfg, _, err := loadConfig(w.globals)
	if err != nil {
		return err
	}
	current, err := state.New(cfg.Paths.StateDir).LoadMembership()
	if err != nil {
		return err
	}
	if current.NetworkID != "" {
		return errors.New("这台电脑已经配对；请先断开原有网络")
	}
	if name != "" {
		cfg.Device.Name = name
	}
	w.mu.Lock()
	if w.pairing {
		w.mu.Unlock()
		return errors.New("已有配对申请正在进行")
	}
	w.pairing = true
	w.pairCode = ""
	w.nasAddress = invite.NASAddress
	w.errorMessage = ""
	w.message = "正在向 NAS 发送配对申请…"
	w.mu.Unlock()
	go func() {
		ctx, cancel := context.WithDeadline(context.Background(), invite.ExpiresAt)
		defer cancel()
		result, err := app.PairDevice(ctx, cfg, invitation, pairProgress{window: w})
		if err == nil {
			cfg.Discovery.StaticPeers = append(cfg.Discovery.StaticPeers, result.NASAddress)
			err = writeConfig(w.globals, cfg, result.NetworkID)
		}
		w.update(func() {
			w.pairing = false
			if err != nil {
				w.errorMessage = err.Error()
				w.message = "配对未完成"
			} else {
				w.message = "NAS 已批准，可以连接"
				w.pairCode = ""
				w.nasAddress = result.NASAddress
			}
		})
	}()
	return nil
}

func (w *clientWindow) connect() error {
	cfg, _, err := loadConfig(w.globals)
	if err != nil {
		return err
	}
	current, err := state.New(cfg.Paths.StateDir).LoadMembership()
	if err != nil || current.NetworkID == "" {
		return errors.New("请先完成 NAS 配对")
	}
	if _, err := app.NewClient(cfg.Paths.Socket).Status(); err == nil {
		return nil
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	w.mu.Lock()
	if w.launchDone != nil {
		select {
		case <-w.launchDone:
		default:
			w.mu.Unlock()
			return errors.New("请先完成或取消管理员授权")
		}
	}
	if w.connecting || w.disconnecting {
		w.mu.Unlock()
		return errors.New("连接操作尚未完成")
	}
	if w.background != 0 {
		code, waitErr := windows.WaitForSingleObject(w.background, 0)
		if waitErr != nil || code != windows.WAIT_OBJECT_0 {
			w.mu.Unlock()
			return errors.New("后台仍在运行，请先断开")
		}
		_ = windows.CloseHandle(w.background)
		w.background = 0
	}
	done := make(chan struct{})
	w.launchDone = done
	w.connecting = true
	w.connectSince = time.Now()
	w.errorMessage = ""
	w.message = "正在请求管理员权限并建立连接…"
	w.mu.Unlock()
	_ = os.Remove(filepath.Join(os.Getenv("LOCALAPPDATA"), "NKNGuard", "last-error.txt"))
	handle, err := runElevated(executable, w.globals.configPath)
	w.mu.Lock()
	w.background = handle
	if err != nil {
		w.connecting = false
		w.errorMessage = err.Error()
	}
	close(done)
	w.mu.Unlock()
	return err
}

func (w *clientWindow) disconnect() error {
	cfg, _, err := loadConfig(w.globals)
	if err != nil {
		return err
	}
	w.mu.Lock()
	if w.disconnecting {
		w.mu.Unlock()
		return errors.New("正在断开，请稍后")
	}
	w.disconnecting = true
	done := w.launchDone
	w.mu.Unlock()
	defer w.update(func() { w.disconnecting = false })
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if done != nil {
		select {
		case <-done:
		case <-ctx.Done():
			return errors.New("请完成或取消管理员授权后，再退出")
		}
	}
	w.mu.Lock()
	handle := w.background
	w.mu.Unlock()
	err = waitForClientStop(ctx, func() (bool, error) {
		if handle == 0 {
			return true, nil
		}
		code, err := windows.WaitForSingleObject(handle, 0)
		return code == windows.WAIT_OBJECT_0, err
	}, app.NewClient(cfg.Paths.Socket).Down)
	if err == nil {
		w.update(func() {
			if w.background != 0 {
				_ = windows.CloseHandle(w.background)
				w.background = 0
			}
			w.launchDone = nil
			w.connecting = false
			w.message = "已断开"
			w.errorMessage = ""
		})
	}
	return err
}

// clientUsageReporter counts this computer in the anonymous usage statistics
// while the window is open. The background service shares the same state
// file, so the switch applies to both.
func clientUsageReporter(g globals) *usagestats.Reporter {
	cfg, _, err := loadConfig(g)
	if err != nil {
		return nil
	}
	node, err := app.OpenNode(cfg)
	if err != nil {
		return nil
	}
	return app.NewUsageReporter(cfg, node.Keystore, nil)
}
