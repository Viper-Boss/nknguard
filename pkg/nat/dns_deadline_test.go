package nat

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestSTUNDNSObeysQueryDeadline(t *testing.T) {
	previous := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	defer func() { net.DefaultResolver = previous }()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	start := time.Now()
	_, err = STUNQuery(context.Background(), conn, "blocked.example.invalid:3478", 30*time.Millisecond)
	if err == nil || time.Since(start) > time.Second {
		t.Fatalf("DNS did not respect STUN timeout: elapsed=%s err=%v", time.Since(start), err)
	}
}
