package nkn

import (
	"context"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/golang/protobuf/proto"
	ncp "github.com/nknorg/ncp-go"
	"github.com/nknorg/ncp-go/pb"
)

func TestCrossSubclientBootstrapOnlyFansOutHandshake(t *testing.T) {
	m := &MultiClient{config: &ClientConfig{RemoteSubClients: 4}}
	handshake, _ := proto.Marshal(&pb.Packet{Handshake: true, ClientIds: []string{"__3__"}})
	data, _ := proto.Marshal(&pb.Packet{SequenceId: 1, Data: []byte("private data")})
	want := []string{"__0__.remote", "__1__.remote", "__2__.remote", "__3__.remote"}
	if got := m.sessionDestinations("remote", "__3__", handshake); !reflect.DeepEqual(got, want) {
		t.Fatalf("handshake cannot reach disjoint IDs: %v", got)
	}
	for _, packet := range [][]byte{data, {0xff}} {
		if got := m.sessionDestinations("remote", "__3__", packet); !reflect.DeepEqual(got, []string{"__3__.remote"}) {
			t.Fatalf("data or invalid packet was broadcast: %v", got)
		}
	}
	m.config.RemoteSubClients = 100
	if got := m.messageDestinations([]string{"remote"}, 3); len(got) != 4 {
		t.Fatalf("unbounded fanout: %v", got)
	}
	m.config.RemoteSubClients = 0
	if got := m.sessionDestinations("remote", "__3__", handshake); !reflect.DeepEqual(got, []string{"__3__.remote"}) {
		t.Fatal("default behaviour changed")
	}
	if got := m.messageDestinations([]string{"remote"}, 1); !reflect.DeepEqual(got, []string{"__1__.remote"}) {
		t.Fatal("upstream message routing changed")
	}
}

// Models the observed failure: the phone has only ID 3; the NAS has only
// ID 0. Messages to the wrong remote ID disappear, as on the real network.
func TestNCPConnectsDisjointSubclientsWithoutBroadcastingData(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	m := &MultiClient{config: &ClientConfig{RemoteSubClients: 4}}
	type frame struct {
		local, remote string
		data          []byte
	}
	toA, toB := make(chan frame, 64), make(chan frame, 64)
	sender := func(remoteAddr string, inbox chan frame) ncp.SendWithFunc {
		return func(local, remote string, data []byte, timeout time.Duration) error {
			for _, dest := range m.sessionDestinations(remoteAddr, remote, data) {
				id := strings.SplitN(dest, ".", 2)[0]
				select {
				case inbox <- frame{local, id, append([]byte(nil), data...)}:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			return nil
		}
	}
	a, err := ncp.NewSession(NewClientAddr("a"), NewClientAddr("b"), []string{"__3__"}, nil, sender("b", toB), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := ncp.NewSession(NewClientAddr("b"), NewClientAddr("a"), []string{"__0__"}, nil, sender("a", toA), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	first := make(chan struct{}, 1)
	pump := func(session *ncp.Session, inbox <-chan frame, own string, notify bool) {
		for {
			select {
			case <-ctx.Done():
				return
			case packet := <-inbox:
				if packet.remote != own {
					continue
				}
				_ = session.ReceiveWith(own, packet.local, packet.data)
				if notify {
					select {
					case first <- struct{}{}:
					default:
					}
				}
			}
		}
	}
	go pump(a, toA, "__3__", false)
	go pump(b, toB, "__0__", true)
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
		t.Fatalf("disjoint bootstrap failed: %v", err)
	}
	select {
	case err := <-accepted:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	written := make(chan error, 1)
	go func() { _, err := a.Write([]byte("test")); written <- err }()
	_ = b.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 4)
	if _, err := io.ReadFull(b, buf); err != nil || string(buf) != "test" {
		t.Fatalf("session data failed: %q %v", buf, err)
	}
	select {
	case err := <-written:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}
