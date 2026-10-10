package mesh

import (
	"fmt"
	"sync"
	"testing"
)

func TestConcurrentPeerAdmissionStaysBounded(t *testing.T) {
	c := New()
	var wg sync.WaitGroup
	for i := 0; i < MaxPeers+128; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c.peerFor(fmt.Sprintf("peer-%d", i))
		}(i)
	}
	wg.Wait()
	if len(c.peers) != MaxPeers {
		t.Fatalf("peer table has %d entries, want %d", len(c.peers), MaxPeers)
	}
	for id, peer := range c.peers {
		if c.peerFor(id) != peer {
			t.Fatal("full table rejected an existing peer")
		}
	}
}
