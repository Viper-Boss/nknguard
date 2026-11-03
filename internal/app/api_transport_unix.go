//go:build !windows

package app

import (
	"context"
	"net"
	"os"
)

func listenLocalAPI(path string) (net.Listener, error) {
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSocket != 0 {
		_ = os.Remove(path)
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err = os.Chmod(path, SocketMode); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}
func dialLocalAPI(ctx context.Context, path string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "unix", path)
}
func removeLocalAPI(path string) { _ = os.Remove(path) }
