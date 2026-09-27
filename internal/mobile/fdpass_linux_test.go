package mobile

import (
	"bufio"
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func sendFD(t *testing.T, path, token string, file *os.File) string {
	t.Helper()
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, _, err := conn.WriteMsgUnix([]byte(token+"\n"), unix.UnixRights(int(file.Fd())), nil); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	line, _ := bufio.NewReader(conn).ReadString('\n')
	return line
}

func TestFDReceiverDeliversByToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tun.sock")
	receiver, err := ListenFD(path)
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode: %v %v", info.Mode(), err)
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()

	result := make(chan int, 1)
	go func() {
		fd, err := receiver.Receive(context.Background(), "abc")
		if err != nil {
			t.Error(err)
		}
		result <- fd
	}()
	time.Sleep(50 * time.Millisecond)
	if reply := sendFD(t, path, "abc", writer); reply != "ok\n" {
		t.Fatalf("reply = %q", reply)
	}
	fd := <-result
	// A descriptor that arrives before its connect command is held for it.
	if reply := sendFD(t, path, "early", writer); reply != "ok\n" {
		t.Fatalf("early reply = %q", reply)
	}
	earlyFD, err := receiver.Receive(context.Background(), "early")
	if err != nil {
		t.Fatal(err)
	}
	_ = unix.Close(earlyFD)
	if reply := sendFD(t, path, "", writer); reply != "rejected\n" {
		t.Fatalf("reply to an empty token = %q", reply)
	}
	received := os.NewFile(uintptr(fd), "received")
	defer received.Close()
	if _, err := received.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 1)
	if _, err := reader.Read(buffer); err != nil || buffer[0] != 'x' {
		t.Fatal("received descriptor is not the pipe that was sent")
	}
}

func TestFDReceiverTimesOut(t *testing.T) {
	receiver, err := ListenFD(filepath.Join(t.TempDir(), "tun.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := receiver.Receive(ctx, "never"); err == nil {
		t.Fatal("expected timeout")
	}
}
