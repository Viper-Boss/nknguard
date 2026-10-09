package ncp

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/nknorg/ncp-go/pb"
)

func TestFullMeshRetainsFourthRemoteChannel(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		s, err := NewSession(&net.TCPAddr{}, &net.TCPAddr{}, []string{"0", "1", "2"}, nil,
			func(string, string, []byte, time.Duration) error { return nil }, &Config{FullMesh: enabled, Linger: 1})
		if err != nil {
			t.Fatal(err)
		}
		err = s.handleHandshakePacket(&pb.Packet{Handshake: true, WindowSize: 4096, Mtu: 1024, ClientIds: []string{"0", "1", "2", "3"}})
		if err != nil {
			t.Fatal(err)
		}
		_, retained := s.connections[connKey("0", "3")]
		if retained != enabled {
			t.Fatalf("enabled=%v retained=%v", enabled, retained)
		}
		_ = s.Close()
	}
}

func TestFullMeshTransfersOverOnlySurvivingAsymmetricPair(t *testing.T) {
	type message struct {
		local, remote string
		data          []byte
	}
	aQueue, bQueue := make(chan message, 256), make(chan message, 256)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	config := &Config{FullMesh: true, InitialRetransmissionTimeout: 200, MaxRetransmissionTimeout: 500, Linger: 1}
	send := func(queue chan message, liveLocal, liveRemote string) SendWithFunc {
		return func(local, remote string, raw []byte, _ time.Duration) error {
			var packet pb.Packet
			_ = proto.Unmarshal(raw, &packet)
			if packet.Handshake {
				local, remote = liveLocal, liveRemote
			}
			if local != liveLocal || remote != liveRemote {
				return nil
			} // unreachable nodes silently lose packets
			select {
			case queue <- message{remote, local, append([]byte(nil), raw...)}:
			case <-ctx.Done():
			}
			return nil
		}
	}
	a, err := NewSession(&net.TCPAddr{Port: 1}, &net.TCPAddr{Port: 2}, []string{"0", "1", "2"}, nil, send(bQueue, "0", "3"), config)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewSession(&net.TCPAddr{Port: 2}, &net.TCPAddr{Port: 1}, []string{"0", "1", "2", "3"}, nil, send(aQueue, "3", "0"), config)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	defer b.Close()
	first := make(chan struct{}, 1)
	pump := func(s *Session, queue chan message) {
		for {
			select {
			case <-ctx.Done():
				return
			case msg := <-queue:
				_ = s.ReceiveWith(msg.local, msg.remote, msg.data)
				if s == b && s.IsEstablished() {
					select {
					case first <- struct{}{}:
					default:
					}
				}
			}
		}
	}
	go pump(a, aQueue)
	go pump(b, bQueue)
	accepted := make(chan error, 1)
	go func() {
		select {
		case <-first:
			accepted <- b.Accept()
		case <-ctx.Done():
			accepted <- ctx.Err()
		}
	}()
	if err := a.Dial(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-accepted:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("accept timeout")
	}
	_ = a.SetDeadline(time.Now().Add(6 * time.Second))
	_ = b.SetDeadline(time.Now().Add(6 * time.Second))
	want := bytes.Repeat([]byte{0, 1, 255, 3}, 512)
	for _, pair := range [][2]*Session{{a, b}, {b, a}} {
		written := make(chan error, 1)
		go func() { _, err := pair[0].Write(want); written <- err }()
		got := make([]byte, len(want))
		if _, err := io.ReadFull(pair[1], got); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatal("payload corrupted")
		}
		if err := <-written; err != nil {
			t.Fatal(err)
		}
	}
}
