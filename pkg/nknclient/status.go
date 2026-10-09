package nknclient

import "time"

// ConnectionStatus measures a recent end-to-end self-message check.
// Measurements stay in memory and do not add blockchain transactions.
type ConnectionStatus struct {
	State       string       `json:"state"`
	CheckedAt   time.Time    `json:"checked_at"`
	LastSuccess time.Time    `json:"last_success"`
	LatencyMS   int64        `json:"latency_ms"`
	LastError   string       `json:"last_error,omitempty"`
	Nodes       []NodeStatus `json:"nodes,omitempty"`
}

// A node socket is not evidence of end-to-end message delivery.
type NodeStatus struct {
	ClientID int    `json:"client_id"`
	Endpoint string `json:"endpoint"`
	Closed   bool   `json:"closed"`
}
