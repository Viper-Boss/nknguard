//go:build windows

package wireguard_test

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Viper-Boss/nknguard/pkg/identity"
	"github.com/Viper-Boss/nknguard/pkg/wireguard"
	"github.com/Viper-Boss/nknguard/pkg/wireguard/userspace"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

// Opt-in integration test: creates only its own temporary tunnel, then removes it.
func TestLiveWindowsOfficialTunnel(t *testing.T) {
	if os.Getenv("NKG_LIVE_WINDOWS") != "1" {
		t.Skip("opt-in administrator test")
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Fatal("requires Windows administrator token")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
	defer cancel()
	dir := t.TempDir()
	host := wireguard.NewHostManager(identity.NewKeystore(filepath.Join(dir, "hostkeys")), fmt.Sprintf("nknguardt%d", os.Getpid()), dir)
	channel := tuntest.NewChannelTUN()
	remote := userspace.New(identity.NewKeystore(filepath.Join(dir, "remotekeys")), func() (tun.Device, error) { return channel.TUN(), nil }, nil)
	if err := remote.EnsureInterface(ctx, wireguard.InterfaceConfig{Name: "remote", Address: "10.253.247.2/24"}); err != nil {
		t.Fatal(err)
	}
	defer remote.Down(context.Background())
	if err := host.EnsureInterface(ctx, wireguard.InterfaceConfig{Address: "10.253.247.1/24"}); err != nil {
		t.Fatal(err)
	}
	defer func() {
		c, done := context.WithTimeout(context.Background(), 15*time.Second)
		defer done()
		if err := host.Down(c); err != nil {
			t.Error("cleanup:", err)
		}
	}()
	hs, rs := host.Status(ctx), remote.Status(ctx)
	for i := 0; hs.ListenPort == 0 && i < 40; i++ {
		time.Sleep(250 * time.Millisecond)
		hs = host.Status(ctx)
	}
	if hs.ListenPort == 0 {
		t.Fatalf("Windows tunnel has no UDP listener: %+v", hs)
	}
	t.Logf("official tunnel ready: port=%d", hs.ListenPort)
	if err := remote.AddPeer(ctx, wireguard.PeerConfig{PublicKey: hs.PublicKey, AllowedIPs: []string{"10.253.247.1/32"}, Endpoint: fmt.Sprintf("127.0.0.1:%d", hs.ListenPort), PersistentKeepalive: 1}); err != nil {
		t.Fatal(err)
	}
	if err := host.AddPeer(ctx, wireguard.PeerConfig{PublicKey: rs.PublicKey, AllowedIPs: []string{"10.253.247.2/32"}, Endpoint: fmt.Sprintf("127.0.0.1:%d", rs.ListenPort), PersistentKeepalive: 1}); err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case packet := <-channel.Inbound:
				if len(packet) < 28 || packet[9] != 17 {
					continue
				}
				p := append([]byte(nil), packet...)
				h := int(p[0]&15) * 4
				if len(p) < h+8 {
					continue
				}
				copy(p[12:16], packet[16:20])
				copy(p[16:20], packet[12:16])
				p[h], p[h+1], p[h+2], p[h+3] = packet[h+2], packet[h+3], packet[h], packet[h+1]
				p[h+6], p[h+7] = 0, 0
				p[10], p[11] = 0, 0
				var sum uint32
				for i := 0; i < h; i += 2 {
					sum += uint32(p[i])<<8 | uint32(p[i+1])
				}
				for sum>>16 != 0 {
					sum = (sum & 65535) + (sum >> 16)
				}
				sum = ^sum
				p[10], p[11] = byte(sum>>8), byte(sum)
				select {
				case channel.Outbound <- p:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	conn, err := net.Dial("udp4", "10.253.247.2:23456")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	want := []byte("nknguard-windows-live-echo")
	buf := make([]byte, 128)
	for i := 0; i < 12; i++ {
		conn.SetDeadline(time.Now().Add(time.Second))
		conn.Write(want)
		n, e := conn.Read(buf)
		if e == nil && bytes.Equal(buf[:n], want) {
			t.Log("dynamic peer: real encrypted UDP round trip passed")
			return
		}
	}
	t.Fatalf("UDP round trip failed after dynamic peer install; host=%+v remote=%+v", host.Status(ctx), remote.Status(ctx))
}
