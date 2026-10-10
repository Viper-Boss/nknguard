//go:build linux

package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/Viper-Boss/nknguard/internal/config"
	"github.com/Viper-Boss/nknguard/pkg/releaseupdate"
)

func updateKind() string {
	exe, _ := os.Executable()
	installed, err := filepath.EvalSymlinks("/var/apps/nknguard/target/bin/nknguard")
	if err == nil && installed == exe {
		return "fnos"
	}
	return "linux"
}

func updateSupported(cfg config.Config) bool {
	if os.Geteuid() != 0 || cfg.SourceFile == "" {
		return false
	}
	if _, err := exec.LookPath("systemd-run"); err != nil {
		return false
	}
	if updateKind() == "fnos" {
		_, err := exec.LookPath("appcenter-cli")
		return err == nil
	}
	_, err := os.Stat("/etc/systemd/system/nknguard.service")
	return err == nil
}

func launchUpdate(cfg config.Config, dir string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "systemd-run", "--quiet", "--collect", "--unit=nknguard-update-"+filepath.Base(dir), "--property=StandardOutput=null", "--property=StandardError=null", exe,
		"--config", cfg.SourceFile, "--state-dir", cfg.Paths.StateDir, "--socket", cfg.Paths.Socket, "update-apply", dir).Run()
}

// ApplyUpdate runs in a separate transient service so stopping the main daemon
// cannot kill the update or rollback. It accepts only root-owned staged jobs.
func ApplyUpdate(cfg config.Config, dir string) (resultErr error) {
	if !updateSupported(cfg) {
		return errors.New("unsupported installation")
	}
	root := filepath.Join(cfg.Paths.StateDir, "updates")
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return err
	}
	realDir, err := filepath.EvalSymlinks(dir)
	if err != nil || filepath.Dir(realDir) != realRoot || !strings.HasPrefix(filepath.Base(realDir), "job-") {
		return errors.New("update job outside private staging directory")
	}
	st, err := os.Stat(realDir)
	if err != nil {
		return err
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != 0 || st.Mode().Perm()&0o077 != 0 {
		return errors.New("update job must be private and owned by root")
	}
	lock := filepath.Join(realRoot, "apply.lock")
	f, err := os.OpenFile(lock, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return errors.New("another update is running")
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	statePath := filepath.Join(cfg.Paths.StateDir, "update-result.json")
	writeState := func(state, message string) {
		raw, _ := json.Marshal(map[string]any{"state": state, "message": message, "time": time.Now().UTC()})
		tmp := statePath + ".tmp"
		if os.WriteFile(tmp, raw, 0o600) == nil {
			_ = os.Rename(tmp, statePath)
		}
	}
	writeState("verifying", "正在验证更新包")
	defer func() {
		if resultErr != nil {
			writeState("failed", resultErr.Error())
		}
		_ = os.RemoveAll(realDir)
	}()
	staged, err := os.MkdirTemp(realDir, "verified-")
	if err != nil {
		return err
	}
	_, next, err := releaseupdate.StageBundle(filepath.Join(realDir, "incoming.zip"), staged, Version, updateKind(), runtime.GOARCH)
	if err != nil {
		return err
	}
	payload := filepath.Join(staged, "payload")
	if updateKind() == "fnos" {
		fpk := filepath.Join(staged, "update.fpk")
		if err := os.Rename(payload, fpk); err != nil {
			return err
		}
		writeState("installing", "正在通过飞牛应用中心升级")
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		if err := exec.CommandContext(ctx, "appcenter-cli", "install-fpk", fpk).Run(); err != nil {
			return fmt.Errorf("fnOS upgrade failed: %w", err)
		}
		writeState("complete", "飞牛应用中心升级完成，请刷新面板")
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	unit, err := exec.CommandContext(ctx, "systemctl", "show", "nknguard.service", "-p", "ExecStart", "--value").Output()
	if err != nil || !strings.Contains(string(unit), "path="+exe+" ;") || !strings.Contains(string(unit), cfg.SourceFile) {
		return errors.New("systemd service does not match the current executable and configuration")
	}
	// Keep the replacement on the executable's filesystem for atomic rename.
	replacement := exe + ".update"
	if err := copyUpdateFile(payload, replacement); err != nil {
		return err
	}
	defer os.Remove(replacement)
	backup := exe + ".previous"
	// Keep the installed path present until the single atomic replacement.
	// A power interruption while preparing the backup still leaves the old executable.
	if err := copyUpdateFile(exe, backup+".new"); err != nil {
		return err
	}
	defer os.Remove(backup + ".new")
	if err := os.Rename(backup+".new", backup); err != nil {
		return err
	}
	writeState("installing", "正在更新服务，配对和配置保持不变")
	if err := exec.CommandContext(ctx, "systemctl", "stop", "nknguard.service").Run(); err != nil {
		return fmt.Errorf("stop service: %w", err)
	}
	rollback := func(cause error) error {
		_ = exec.CommandContext(ctx, "systemctl", "stop", "nknguard.service").Run()
		if err := os.Rename(backup, exe); err != nil {
			return fmt.Errorf("update failed (%v); restore previous binary: %w", cause, err)
		}
		if err := exec.CommandContext(ctx, "systemctl", "start", "nknguard.service").Run(); err != nil {
			return fmt.Errorf("previous binary restored but restart failed: %w", err)
		}
		return fmt.Errorf("已恢复上一版：%w", cause)
	}
	if err := os.Rename(replacement, exe); err != nil {
		return rollback(err)
	}
	if err := exec.CommandContext(ctx, "systemctl", "start", "nknguard.service").Run(); err != nil {
		return rollback(err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("unix", cfg.Paths.Socket, time.Second)
		if err == nil {
			_ = conn.Close()
			status, e := NewClient(cfg.Paths.Socket).Status()
			if e == nil && strings.TrimPrefix(status.Version, "v") == strings.TrimPrefix(next, "v") {
				writeState("complete", "已更新到 "+next+"；上一版程序保留为 .previous")
				return nil
			}
		}
		time.Sleep(time.Second)
	}
	return rollback(errors.New("new service did not become healthy within 30 seconds"))
}

func copyUpdateFile(source, target string) error {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	if err == nil {
		err = out.Sync()
	}
	closeErr := out.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(target)
	}
	return err
}
