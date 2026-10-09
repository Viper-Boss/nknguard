package nknclient

import "time"

// ConnectionStatus measures a recent end-to-end self-message check.
// Measurements stay in memory and do not add blockchain transactions.
type ConnectionStatus struct {
	State       string    `json:"state"`
	CheckedAt   time.Time `json:"checked_at"`
	LastSuccess time.Time `json:"last_success"`
	LatencyMS   int64     `json:"latency_ms"`
}
