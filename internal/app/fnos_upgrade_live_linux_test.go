//go:build linux

package app

import (
	"context"
	"crypto/sha256"
	"fmt"
	"github.com/Viper-Boss/nknguard/pkg/releaseupdate"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// Explicit maintainer opt-in bootstrap for older installed helpers that cannot
// upgrade in place. It uses the same signed bundle verification and native
// upgrade implementation as the shipped updater, never the unsafe CLI fallback.
func TestLiveFnosSignedUpgrade(t *testing.T) {
	bundle := os.Getenv("NKG_LIVE_FNOS_BUNDLE")
	if bundle == "" {
		t.Skip("explicit maintainer upgrade only")
	}
	if os.Geteuid() != 0 {
		t.Fatal("requires root")
	}
	socket := os.Getenv("NKG_LIVE_FNOS_SOCKET")
	stateDir := os.Getenv("NKG_LIVE_FNOS_STATE")
	cfg := os.Getenv("NKG_LIVE_FNOS_CONFIG")
	if socket == "" || stateDir == "" || cfg == "" {
		t.Fatal("explicit local paths required")
	}
	lock, err := acquireInstanceLock(filepath.Join(stateDir, "updates", "apply.lock"))
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	before, err := NewClient(socket).Status()
	if err != nil {
		t.Fatal(err)
	}
	oldConfig, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	configHash := sha256.Sum256(oldConfig)
	dir := t.TempDir()
	_, next, err := releaseupdate.StageBundle(bundle, dir, before.Version, "fnos", runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	target := os.Getenv("NKG_LIVE_FNOS_TARGET")
	if !sameUpdateVersion(next, target) {
		t.Fatal("target version mismatch")
	}
	payload := filepath.Join(dir, "update.fpk")
	if err = os.Rename(filepath.Join(dir, "payload"), payload); err != nil {
		t.Fatal(err)
	}
	taskID := ""
	completed := false
	failure := "维护任务未完成，需检查应用中心"
	save := func(state, message string) {
		if err := atomicUpdateJSON(filepath.Join(stateDir, "update-result.json"), map[string]any{"state": state, "message": message, "version": next, "task_id": taskID, "time": time.Now().UTC()}); err != nil {
			t.Log(err)
		}
	}
	defer func() {
		if !completed {
			save("failed", failure)
		}
	}()
	save("installing", "已验证签名，正在通过飞牛原生升级接口更新")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	client := newFnosUpgradeClient(fnosCenterSocket, socket)
	defer client.http.CloseIdleConnections()
	err = client.upgrade(ctx, payload, next, func(id string) {
		taskID = id
		save("installing", "飞牛升级任务已提交，等待运行版本确认")
	})
	if err != nil {
		failure = err.Error()
		t.Fatal(err)
	}
	after, err := NewClient(socket).Status()
	if err != nil {
		failure = err.Error()
		t.Fatal(err)
	}
	if before.DeviceID != after.DeviceID || before.NetworkID != after.NetworkID || before.VirtualIP != after.VirtualIP {
		failure = "升级后设备身份或虚拟地址改变"
		t.Fatal(failure)
	}
	newConfig, err := os.ReadFile(cfg)
	if err != nil || sha256.Sum256(newConfig) != configHash {
		failure = "升级后配置文件发生变化，请检查备份"
		t.Fatal(failure)
	}
	completed = true
	save("complete", fmt.Sprintf("已更新到 %s，安装版本、运行版本与设备身份均已确认", next))
	t.Logf("upgraded %s -> %s; identity, overlay address and configuration preserved", before.Version, after.Version)
}
