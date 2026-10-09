package directice

import (
	"bytes"
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

func testConfig() Config {
	return Config{IncludeLoopback: true, Interfaces: func() ([]net.Addr, error) {
		return []net.Addr{&net.IPNet{IP: net.IPv4(127, 0, 0, 1), Mask: net.CIDRMask(8, 32)}}, nil
	}}
}

func TestAgentsPreserveDatagramsAndClose(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	a, ad, err := testConfig().Prepare(ctx, strings.Repeat("a", 32))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, bd, err := testConfig().Prepare(ctx, ad.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	done := make(chan net.Conn, 1)
	errChan := make(chan error, 1)
	go func() {
		conn, err := b.Connect(ctx, ad, false)
		if err != nil {
			errChan <- err
		} else {
			done <- conn
		}
	}()
	ac, err := a.Connect(ctx, bd, true)
	if err != nil {
		t.Fatal(err)
	}
	var bc net.Conn
	select {
	case bc = <-done:
	case err := <-errChan:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal("connect timed out")
	}
	for _, direction := range [][2]net.Conn{{ac, bc}, {bc, ac}} {
		for _, size := range []int{1, 148, 1328, 2048} {
			want := bytes.Repeat([]byte{byte(size % 251)}, size)
			if _, err := direction[0].Write(want); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, 4096)
			n, err := direction[1].Read(got)
			if err != nil || !bytes.Equal(got[:n], want) {
				t.Fatalf("packet size %d: n=%d err=%v", size, n, err)
			}
		}
	}
	read := make(chan error, 1)
	go func() { _, err := ac.Read(make([]byte, 128)); read <- err }()
	a.Close()
	select {
	case err := <-read:
		if err == nil {
			t.Fatal("read survived close")
		}
	case <-time.After(time.Second):
		t.Fatal("reader leaked")
	}
}

func TestWrongICECredentialsCannotConnect(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 600*time.Millisecond)
	defer cancel()
	a, ad, err := testConfig().Prepare(ctx, strings.Repeat("b", 32))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, bd, err := testConfig().Prepare(ctx, ad.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	bd.Password = strings.Repeat("wrong", 8)
	go func() { _, _ = b.Connect(ctx, ad, false) }()
	if conn, err := a.Connect(ctx, bd, true); err == nil || conn != nil {
		t.Fatal("wrong credentials established a connection")
	}
}

func TestDescriptionBounds(t *testing.T) {
	if err := Validate(Description{ID: strings.Repeat("a", 32), Ufrag: "abcd", Password: strings.Repeat("p", 32),
		Candidates: []string{"1 1 udp 1 0.0.0.0 1234 typ host"}}); err == nil {
		t.Fatal("unspecified endpoint accepted")
	}
}
