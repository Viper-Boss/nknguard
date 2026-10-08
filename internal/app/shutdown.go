package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Viper-Boss/nknguard/internal/config"
	"github.com/Viper-Boss/nknguard/internal/state"
	"github.com/Viper-Boss/nknguard/pkg/identity"
	"github.com/Viper-Boss/nknguard/pkg/wireguard"
)

// CleanupStoppedTunnel repairs a failed shutdown without reconnecting. Both
// locks prevent this command from tearing down a running daemon's interface.
func CleanupStoppedTunnel(cfg config.Config) error {
	if !hasTunnelPrivilege() {
		return errors.New("cleanup requires administrator privileges")
	}
	lock, err := acquireInstanceLock(filepath.Join(cfg.Paths.StateDir, "daemon.lock"))
	if err != nil {
		return err
	}
	defer lock.Close()
	apiLock, err := acquireInstanceLock(cfg.Paths.Socket + ".lock")
	if err != nil {
		return err
	}
	defer apiLock.Close()
	store := state.New(cfg.Paths.StateDir)
	if err := store.SaveShutdown(state.Shutdown{}); err != nil {
		return err
	}
	wg := wireguard.NewHostManager(wireguard.FromIdentityKeystore(identity.NewKeystore(cfg.KeystoreDir())), cfg.WireGuard.Interface, cfg.Paths.StateDir)
	return cleanupTunnel(wg, store)
}

func cleanupTunnel(wg wireguard.Manager, store *state.Store) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := wg.Down(ctx)
	if err != nil {
		err = fmt.Errorf("tunnel cleanup failed: %w", err)
	}
	result := state.Shutdown{Completed: true}
	if err != nil {
		result.Error = err.Error()
	}
	return errors.Join(err, store.SaveShutdown(result))
}

// CheckShutdown checks the durable result after the process and API disappeared.
// Old versions did not write this file; a never-started client is also harmless.
func CheckShutdown(stateDir string) error {
	result, err := state.New(stateDir).LoadShutdown()
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("无法读取隧道清理结果: %w", err)
	}
	if !result.Completed {
		return errors.New("后台异常退出，尚未确认 WireGuard 清理，请重新连接后再断开")
	}
	if result.Error != "" {
		return errors.New(result.Error)
	}
	return nil
}
