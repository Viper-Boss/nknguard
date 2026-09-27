package mobile

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// FDReceiver takes the VpnService TUN file descriptor from the app.
//
// The app cannot give a child process an extra file descriptor at exec time,
// so it connects to this Unix socket, which lives in its private files
// directory, and sends the descriptor as SCM_RIGHTS ancillary data together
// with the one-time token of the matching connect command. Connections from
// any other user id are refused before anything is read.
type FDReceiver struct {
	listener *net.UnixListener
	path     string

	mu      sync.Mutex
	waiting map[string]chan int
	// early holds descriptors that arrived before the connect command that
	// waits for them: the app sends both at once, and either may win.
	early  map[string]earlyFD
	closed bool
	done   chan struct{}
}

type earlyFD struct {
	fd int
	at time.Time
}

// earlyLimit bounds descriptors held for a connect that has not arrived.
const earlyLimit = 4

// ListenFD creates the socket at path.
func ListenFD(path string) (*FDReceiver, error) {
	if info, err := os.Lstat(path); err == nil && info.Mode()&fs.ModeSocket != 0 {
		_ = os.Remove(path)
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = listener.Close()
		return nil, err
	}
	receiver := &FDReceiver{listener: listener, path: path, waiting: make(map[string]chan int), early: make(map[string]earlyFD), done: make(chan struct{})}
	go receiver.acceptLoop()
	return receiver, nil
}

// Receive waits for the descriptor sent with token.
func (r *FDReceiver) Receive(ctx context.Context, token string) (int, error) {
	if token == "" {
		return -1, errors.New("missing TUN token")
	}
	delivery := make(chan int, 1)
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return -1, errors.New("TUN socket closed")
	}
	if held, ok := r.early[token]; ok {
		delete(r.early, token)
		r.mu.Unlock()
		return held.fd, nil
	}
	r.waiting[token] = delivery
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		delete(r.waiting, token)
		r.mu.Unlock()
	}()
	select {
	case fd := <-delivery:
		return fd, nil
	case <-ctx.Done():
		// A descriptor that arrives after we gave up must not leak.
		select {
		case fd := <-delivery:
			_ = unix.Close(fd)
		default:
		}
		return -1, fmt.Errorf("the app did not hand over the VPN interface: %w", ctx.Err())
	}
}

// Close removes the socket.
func (r *FDReceiver) Close() error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	for token, held := range r.early {
		_ = unix.Close(held.fd)
		delete(r.early, token)
	}
	r.mu.Unlock()
	err := r.listener.Close()
	<-r.done
	_ = os.Remove(r.path)
	return err
}

func (r *FDReceiver) acceptLoop() {
	defer close(r.done)
	for {
		conn, err := r.listener.AcceptUnix()
		if err != nil {
			return
		}
		r.handle(conn)
	}
}

func (r *FDReceiver) handle(conn *net.UnixConn) {
	defer conn.Close()
	if !sameUser(conn) {
		return
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	var (
		message []byte
		fds     []int
	)
	buffer := make([]byte, 128)
	oob := make([]byte, unix.CmsgSpace(4*4))
	for len(message) < 256 && !bytes.Contains(message, []byte{'\n'}) {
		n, oobn, _, _, err := conn.ReadMsgUnix(buffer, oob)
		if oobn > 0 {
			if messages, parseErr := unix.ParseSocketControlMessage(oob[:oobn]); parseErr == nil {
				for _, control := range messages {
					if rights, err := unix.ParseUnixRights(&control); err == nil {
						fds = append(fds, rights...)
					}
				}
			}
		}
		message = append(message, buffer[:n]...)
		if err != nil || n == 0 {
			break
		}
	}
	token := strings.TrimSpace(string(message))
	if len(fds) == 0 {
		return
	}
	for _, extra := range fds[1:] {
		_ = unix.Close(extra)
	}
	r.mu.Lock()
	delivery, ok := r.waiting[token]
	if !ok {
		accepted := r.holdEarlyLocked(token, fds[0])
		r.mu.Unlock()
		if accepted {
			_, _ = conn.Write([]byte("ok\n"))
		} else {
			_, _ = conn.Write([]byte("rejected\n"))
		}
		return
	}
	r.mu.Unlock()
	select {
	case delivery <- fds[0]:
		_, _ = conn.Write([]byte("ok\n"))
	default:
		_ = unix.Close(fds[0])
	}
}

func (r *FDReceiver) holdEarlyLocked(token string, fd int) bool {
	now := time.Now()
	for held, entry := range r.early {
		if now.Sub(entry.at) > 30*time.Second {
			_ = unix.Close(entry.fd)
			delete(r.early, held)
		}
	}
	if previous, ok := r.early[token]; ok {
		_ = unix.Close(previous.fd)
	}
	if token == "" || r.closed || len(r.early) >= earlyLimit {
		_ = unix.Close(fd)
		return false
	}
	r.early[token] = earlyFD{fd: fd, at: now}
	return true
}

func sameUser(conn *net.UnixConn) bool {
	raw, err := conn.SyscallConn()
	if err != nil {
		return false
	}
	var cred *unix.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil || credErr != nil {
		return false
	}
	return int(cred.Uid) == os.Getuid()
}
