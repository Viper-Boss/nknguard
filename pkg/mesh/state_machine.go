// Package mesh is the controller: it turns discovered peers into working
// tunnels and keeps them working.
//
// One peer, one state machine, one goroutine. That constraint is what keeps a
// node with twenty peers from having two hundred goroutines whose lifetimes
// nobody can account for, and it is why every long-running function here takes
// a context and returns when it is cancelled.
package mesh

import (
	"fmt"
	"time"
)

// PeerState is where a peer is in the path-establishment sequence.
type PeerState string

const (
	// StateUnknown is a peer we have heard of but not looked at.
	StateUnknown PeerState = "UNKNOWN"
	// StateDiscovered means a verified record exists.
	StateDiscovered PeerState = "DISCOVERED"
	// StateSignaling means the HELLO exchange is in flight.
	StateSignaling PeerState = "SIGNALING"
	// StateCandidateExchange means both sides are trading addresses.
	StateCandidateExchange PeerState = "CANDIDATE_EXCHANGE"
	// StatePunching means probes are in the air.
	StatePunching PeerState = "PUNCHING"
	// StateWGConnecting means the peer is installed and we are waiting for a
	// handshake. It is a distinct state because "configured" and "working" are
	// different things and conflating them is how a status display lies.
	StateWGConnecting PeerState = "WG_CONNECTING"
	// StateDirect means a WireGuard handshake happened recently over a direct
	// endpoint.
	StateDirect PeerState = "DIRECT"
	// StateRelayConnecting means we are opening the fallback.
	StateRelayConnecting PeerState = "RELAY_CONNECTING"
	// StateRelay means traffic is flowing through the relay.
	StateRelay PeerState = "RELAY"
	// StateDegraded means neither path is working but the peer is still known
	// and still being retried.
	StateDegraded PeerState = "DEGRADED"
	// StateOffline means the peer's record has expired and nothing is being
	// attempted until it reappears.
	StateOffline PeerState = "OFFLINE"
)

// Event drives a transition.
type Event string

const (
	EventRecordSeen     Event = "record_seen"
	EventRecordExpired  Event = "record_expired"
	EventHelloSent      Event = "hello_sent"
	EventHelloReceived  Event = "hello_received"
	EventCandidatesGot  Event = "candidates_received"
	EventPunchStarted   Event = "punch_started"
	EventPunchSucceeded Event = "punch_succeeded"
	EventPunchFailed    Event = "punch_failed"
	EventHandshakeOK    Event = "wg_handshake_ok"
	EventHandshakeStale Event = "wg_handshake_stale"
	EventRelayOpening   Event = "relay_opening"
	EventRelayOpen      Event = "relay_open"
	EventRelayFailed    Event = "relay_failed"
	EventShutdown       Event = "shutdown"
)

// ErrIllegalTransition is returned for an event the current state does not
// accept. It is an error rather than a silent no-op so that a bug in the
// controller shows up in a test instead of as a peer that mysteriously stalls.
type ErrIllegalTransition struct {
	From  PeerState
	Event Event
}

func (e ErrIllegalTransition) Error() string {
	return fmt.Sprintf("mesh: event %q is not legal in state %q", e.Event, e.From)
}

// transitions is the whole state machine as data.
//
// Writing it as a table rather than a switch means the legal moves can be
// read, tested and diffed in one place, and an event that should not be
// possible cannot be smuggled in by an if-statement three files away.
var transitions = map[PeerState]map[Event]PeerState{
	StateUnknown: {
		EventRecordSeen: StateDiscovered,
		EventShutdown:   StateOffline,
	},
	StateDiscovered: {
		EventHelloSent:     StateSignaling,
		EventHelloReceived: StateSignaling,
		EventRecordExpired: StateOffline,
		EventShutdown:      StateOffline,
	},
	StateSignaling: {
		EventHelloReceived: StateSignaling,
		EventCandidatesGot: StateCandidateExchange,
		EventRecordExpired: StateOffline,
		EventRelayOpening:  StateRelayConnecting,
		EventShutdown:      StateOffline,
	},
	StateCandidateExchange: {
		EventPunchStarted:  StatePunching,
		EventCandidatesGot: StateCandidateExchange,
		EventHandshakeOK:   StateDirect,
		EventRelayOpening:  StateRelayConnecting,
		EventRecordExpired: StateOffline,
		EventShutdown:      StateOffline,
	},
	StatePunching: {
		EventPunchSucceeded: StateWGConnecting,
		EventPunchFailed:    StateRelayConnecting,
		EventCandidatesGot:  StateCandidateExchange,
		EventRecordExpired:  StateOffline,
		EventShutdown:       StateOffline,
	},
	StateWGConnecting: {
		EventHandshakeOK:    StateDirect,
		EventHandshakeStale: StateRelayConnecting,
		EventCandidatesGot:  StateCandidateExchange,
		EventRelayOpening:   StateRelayConnecting,
		EventRecordExpired:  StateOffline,
		EventShutdown:       StateOffline,
	},
	StateDirect: {
		EventHandshakeOK: StateDirect,
		// A stale handshake on a direct path goes back to candidate exchange,
		// not straight to the relay: the usual cause is roaming, and the cheap
		// fix is a new endpoint rather than a relayed session.
		EventHandshakeStale: StateCandidateExchange,
		EventCandidatesGot:  StateDirect,
		EventRecordExpired:  StateDirect,
		EventShutdown:       StateOffline,
	},
	StateRelayConnecting: {
		EventRelayOpen:      StateRelay,
		EventRelayFailed:    StateDegraded,
		EventPunchSucceeded: StateWGConnecting,
		EventHandshakeOK:    StateDirect,
		EventRecordExpired:  StateOffline,
		EventShutdown:       StateOffline,
	},
	StateRelay: {
		// The relay keeps probing for a direct path; these two events are how
		// it gets back, and they are what makes the fallback temporary rather
		// than permanent.
		EventPunchSucceeded: StateWGConnecting,
		EventHandshakeOK:    StateDirect,
		EventCandidatesGot:  StateRelay,
		EventRelayFailed:    StateDegraded,
		EventRecordExpired:  StateRelay,
		EventShutdown:       StateOffline,
	},
	StateDegraded: {
		EventRecordSeen:     StateDiscovered,
		EventCandidatesGot:  StateCandidateExchange,
		EventRelayOpening:   StateRelayConnecting,
		EventPunchSucceeded: StateWGConnecting,
		EventHandshakeOK:    StateDirect,
		EventRecordExpired:  StateOffline,
		EventShutdown:       StateOffline,
	},
	StateOffline: {
		EventRecordSeen: StateDiscovered,
		EventShutdown:   StateOffline,
	},
}

// Next returns the state an event leads to.
func Next(from PeerState, event Event) (PeerState, error) {
	allowed, ok := transitions[from]
	if !ok {
		return from, ErrIllegalTransition{From: from, Event: event}
	}
	to, ok := allowed[event]
	if !ok {
		return from, ErrIllegalTransition{From: from, Event: event}
	}
	return to, nil
}

// Observed events report what the data plane is actually doing, and they are
// legal from every live state. A handshake seen on the interface means the
// tunnel is up, whatever step of the signalling dance this side thought it was
// on — the other side may have driven the whole thing, or a HELLO may have
// arrived before this side knew the sender. Refusing the observation because
// the bookkeeping is behind is how a status display ends up saying SIGNALING
// about a tunnel that is carrying traffic.
func init() {
	observed := map[Event]PeerState{
		EventHandshakeOK: StateDirect,
		EventRelayOpen:   StateRelay,
	}
	for state, allowed := range transitions {
		if state == StateUnknown || state == StateOffline {
			continue
		}
		for event, target := range observed {
			if _, explicit := allowed[event]; !explicit {
				allowed[event] = target
			}
		}
	}
}

// Established reports whether a state means traffic can flow.
func Established(state PeerState) bool {
	return state == StateDirect || state == StateRelay
}

// Transition is a recorded state change, kept in a short ring per peer so that
// `nknguard status` can answer "what happened to this peer" without a log
// search.
type Transition struct {
	At    time.Time `json:"at"`
	From  PeerState `json:"from"`
	To    PeerState `json:"to"`
	Event Event     `json:"event"`
}
