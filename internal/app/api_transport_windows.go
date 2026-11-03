//go:build windows

package app

import (
	"context"
	"crypto/sha256"
	"fmt"
	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Hash the configured identity path, never its contents: the endpoint remains
// short even for long Unicode profiles. The DACL grants only this user/SYSTEM.
func localPipeName(path string) (string, error) {
	full, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(strings.ToLower(filepath.Clean(full))))
	return fmt.Sprintf(`\\.\pipe\NKNGuard-%x`, sum[:20]), nil
}
func listenLocalAPI(path string) (net.Listener, error) {
	name, err := localPipeName(path)
	if err != nil {
		return nil, err
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	return winio.ListenPipe(name, &winio.PipeConfig{SecurityDescriptor: "D:P(A;;GA;;;SY)(A;;GA;;;" + user.User.Sid.String() + ")", InputBufferSize: 65536, OutputBufferSize: 65536})
}
func dialLocalAPI(ctx context.Context, path string) (net.Conn, error) {
	name, err := localPipeName(path)
	if err != nil {
		return nil, err
	}
	// A newly upgraded GUI may still be talking to the old AF_UNIX daemon.
	if info, e := os.Lstat(path); e == nil && info.Mode()&os.ModeSocket != 0 {
		short, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		conn, e := winio.DialPipeContext(short, name)
		cancel()
		if e == nil {
			return conn, nil
		}
		var d net.Dialer
		return d.DialContext(ctx, "unix", path)
	}
	conn, err := winio.DialPipeContext(ctx, name)
	if err != nil {
		return nil, &net.OpError{Op: "dial", Net: "pipe", Err: err}
	}
	return conn, nil
}
func removeLocalAPI(string) {} // Closing the last pipe handle removes the endpoint.
