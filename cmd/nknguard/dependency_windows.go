//go:build windows

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/Viper-Boss/nknguard/pkg/wireguard"
	"golang.org/x/sys/windows"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func installWireGuardDependency() error {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return errors.New("需要管理员授权以安装 WireGuard")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	path := filepath.Join(filepath.Dir(exe), "deps", "wireguard-amd64-1.1.1.msi")
	file, err := os.Open(path)
	if err != nil {
		return errors.New("缺少随附的 WireGuard 安装包，请重新下载安装包或解压完整便携包")
	}
	defer file.Close()
	sum := sha256.New()
	if _, err = io.Copy(sum, file); err != nil {
		return err
	}
	if hex.EncodeToString(sum.Sum(nil)) != "7bfed60ad61b785c914b38b61555a975488e1d3ec472dbfb2fcdf498fca75242" {
		return errors.New("WireGuard 安装包校验失败，请重新下载")
	}
	file.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, filepath.Join(os.Getenv("SystemRoot"), "System32", "msiexec.exe"), "/i", path, "/qn", "/norestart")
	command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	err = command.Run()
	if err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 3010 {
			return fmt.Errorf("WireGuard 安装失败: %w", err)
		}
	}
	if state, _ := wireguard.NewHostManager(nil, "nknguard", "").Supported(ctx); state == wireguard.StateToolsMissing {
		return errors.New("WireGuard 尚未就绪，请重启 Windows 后重试")
	}
	return nil
}
func (w *clientWindow) installDependency() {
	w.mu.Lock()
	if w.installingDependency {
		w.mu.Unlock()
		return
	}
	w.installingDependency = true
	w.mu.Unlock()
	w.update(func() { w.message = "正在安装官方 WireGuard，请允许管理员授权…"; w.errorMessage = "" })
	go func() {
		defer w.update(func() { w.installingDependency = false })
		exe, err := os.Executable()
		var handle windows.Handle
		if err == nil {
			handle, err = runElevatedCommand(exe, w.globals.configPath, "install-wireguard")
		}
		if err == nil {
			defer windows.CloseHandle(handle)
			result, e := windows.WaitForSingleObject(handle, 240000)
			if e != nil {
				err = e
			} else if result != windows.WAIT_OBJECT_0 {
				err = errors.New("WireGuard 安装仍在进行，请稍后重试")
			} else {
				var code uint32
				err = windows.GetExitCodeProcess(handle, &code)
				if err == nil && code != 0 {
					raw, _ := os.ReadFile(filepath.Join(os.Getenv("LOCALAPPDATA"), "NKNGuard", "last-error.txt"))
					err = fmt.Errorf("WireGuard 安装未完成: %s", strings.TrimSpace(string(raw)))
				}
			}
		}
		w.update(func() {
			if err != nil {
				w.errorMessage = err.Error()
				w.message = "WireGuard 安装未完成"
			} else {
				w.message = "WireGuard 已安装，可以连接 NAS"
			}
		})
	}()
}
