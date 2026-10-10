package protocol

// MessageType names a control message. They are strings rather than integers
// so a packet capture or a log line is readable without a lookup table, and so
// an unknown type from a newer peer can be logged by name and dropped.
type MessageType string

const (
	TypeHello        MessageType = "HELLO"
	TypePeerInfo     MessageType = "PEER_INFO"
	TypeCandidate    MessageType = "CANDIDATE"
	TypePunchRequest MessageType = "PUNCH_REQUEST"
	TypePunchAck     MessageType = "PUNCH_ACK"
	TypeICEOffer     MessageType = "ICE_OFFER"
	TypeICEAnswer    MessageType = "ICE_ANSWER"
	TypeWGReady      MessageType = "WG_READY"
	TypeKeepalive    MessageType = "KEEPALIVE"
	TypeRekey        MessageType = "REKEY"
	TypeRouteUpdate  MessageType = "ROUTE_UPDATE"
	TypeRelayRequest MessageType = "RELAY_REQUEST"
	TypeRelayReady   MessageType = "RELAY_READY"
	TypeDisconnect   MessageType = "DISCONNECT"
	TypeError        MessageType = "ERROR"
	TypePairRequest  MessageType = "PAIR_REQUEST"
	TypePairApproval MessageType = "PAIR_APPROVAL"
)

// ErrorCode is carried in a TypeError payload.
type ErrorCode string

const (
	ErrorVersionUnsupported ErrorCode = "VERSION_UNSUPPORTED"
	ErrorNotAuthorized      ErrorCode = "NOT_AUTHORIZED"
	ErrorUnknownNetwork     ErrorCode = "UNKNOWN_NETWORK"
	ErrorRateLimited        ErrorCode = "RATE_LIMITED"
	ErrorMalformed          ErrorCode = "MALFORMED"
	ErrorInternal           ErrorCode = "INTERNAL"
)

// Hello opens a conversation between two devices.
type Hello struct {
	Versions     VersionRange `json:"versions"`
	Capabilities []string     `json:"capabilities"`
	DeviceName   string       `json:"device_name,omitempty"`
	// Binding is the sender's signed key binding. The receiver checks it
	// before trusting the WireGuard key in any later message.
	Binding []byte `json:"binding,omitempty"`
}

// PairRequest is signed by the new device but requires an owner's local
// approval. The QR token only opens this request path; it grants no access.
type PairRequest struct {
	Token              string `json:"token"`
	Name               string `json:"name"`
	NKNAddress         string `json:"nkn_address"`
	WireGuardPublicKey string `json:"wireguard_public_key"`
}

// PairApproval travels in an NKN end-to-end encrypted message addressed to
// the requester's NKN identity. It is also signed by the NAS root identity.
type PairApproval struct {
	JoinSecret  string `json:"join_secret"`
	NASID       string `json:"nas_id"`
	NASAddress  string `json:"nas_address"`
	InviteToken string `json:"invite_token"`
}

// PeerInfo carries the sender's own signed peer record. It is the one message
// a node accepts from a device it has not admitted yet, because the payload is
// its own proof: the record is signed by the sender's root key and carries the
// membership proof. It is how two nodes that only know each other's transport
// address — from an NKN topic, a static list, a QR code — become peers.
type PeerInfo struct {
	Record []byte `json:"record"`
	// WantReply asks the receiver to answer with its own record, which is what
	// makes a one-sided introduction symmetric.
	WantReply    bool   `json:"want_reply,omitempty"`
	ConnectionID string `json:"connection_id,omitempty"`
	ConnectUntil int64  `json:"connect_until,omitempty"`
}

// CandidateSet is the sender's current view of how it can be reached.
type CandidateSet struct {
	WireGuardPublicKey string   `json:"wireguard_public_key,omitempty"`
	Candidates         []byte   `json:"candidates"`
	VirtualIPs         []string `json:"virtual_ips,omitempty"`
}

// PunchRequest asks the peer to start sending probes at the same time we do.
// Round groups the two sides' attempts so a late reply from an old round is
// not mistaken for progress on the current one.
type PunchRequest struct {
	Round      uint32 `json:"round"`
	Candidates []byte `json:"candidates"`
	// StartAtUnixMilli is a wall-clock rendezvous. Both sides start probing
	// near the same instant, which is what makes the NAT mappings line up.
	StartAtUnixMilli int64 `json:"start_at_unix_milli"`
	// Token ties the two sides' probes together when the userspace punch
	// strategy is in use. The WireGuard strategy ignores it: WireGuard's own
	// handshake authenticates the path.
	Token []byte `json:"token,omitempty"`
}

// PunchAck answers a PunchRequest.
type PunchAck struct {
	Round    uint32 `json:"round"`
	Accepted bool   `json:"accepted"`
	Reason   string `json:"reason,omitempty"`
}

// WGReady says the sender has the peer configured and is waiting for traffic.
type WGReady struct {
	WireGuardPublicKey string `json:"wireguard_public_key"`
	Endpoint           string `json:"endpoint,omitempty"`
	VirtualIP          string `json:"virtual_ip,omitempty"`
}

// RelayRequest asks to fall back to a relayed path.
type RelayRequest struct {
	Reason string `json:"reason,omitempty"`
}

// RelayReady confirms the relayed path is open.
type RelayReady struct {
	SessionID string `json:"session_id"`
}

// Disconnect is a courtesy: it lets the peer tear down immediately instead of
// waiting for a timeout.
type Disconnect struct {
	Reason       string `json:"reason,omitempty"`
	ConnectionID string `json:"connection_id,omitempty"`
}

// Error reports a refusal. It never carries key material or the offending
// message back to the sender.
type Error struct {
	Code    ErrorCode `json:"code"`
	Message string    `json:"message,omitempty"`
}
