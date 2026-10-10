package discovery

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/Viper-Boss/nknguard/pkg/nat"
)

// ContentID identifies connection information independently of its lease.
// Keys, authorization proof, addresses and capabilities remain in the hash.
func ContentID(record PeerRecord) string {
	r := record
	r.Sequence, r.IssuedAt, r.ExpiresAt, r.Signature = 0, 0, 0, nil
	r.Candidates = append([]nat.EndpointCandidate(nil), record.Candidates...)
	for i := range r.Candidates {
		r.Candidates[i].ObservedAt, r.Candidates[i].ExpiresAt = 0, 0
	}
	raw, _ := json.Marshal(r)
	hash := sha256.Sum256(raw)
	return hex.EncodeToString(hash[:])
}

// Renewal carries only the changing fields of a signed record. Reconstructing
// the record must still pass its original root signature and freshness checks.
// This is not a lease that can extend arbitrary cached or modified addresses.
type Renewal struct {
	ContentID      string     `json:"content_id"`
	Sequence       uint64     `json:"sequence"`
	IssuedAt       int64      `json:"issued_at"`
	ExpiresAt      int64      `json:"expires_at"`
	CandidateTimes [][2]int64 `json:"candidate_times,omitempty"`
	Signature      []byte     `json:"signature"`
}

func NewRenewal(record PeerRecord) Renewal {
	r := Renewal{ContentID: ContentID(record), Sequence: record.Sequence, IssuedAt: record.IssuedAt, ExpiresAt: record.ExpiresAt, Signature: record.Signature}
	for _, candidate := range record.Candidates {
		r.CandidateTimes = append(r.CandidateTimes, [2]int64{candidate.ObservedAt, candidate.ExpiresAt})
	}
	return r
}

var ErrRenewalBase = errors.New("discovery: renewal needs current full record")

func (r Renewal) Apply(previous PeerRecord, networkID string, now time.Time) (PeerRecord, error) {
	if previous.DeviceID == "" || len(r.ContentID) != 64 || r.ContentID != ContentID(previous) || len(r.CandidateTimes) != len(previous.Candidates) || len(r.CandidateTimes) > nat.MaxCandidates {
		return PeerRecord{}, ErrRenewalBase
	}
	next := previous
	next.Sequence, next.IssuedAt, next.ExpiresAt, next.Signature = r.Sequence, r.IssuedAt, r.ExpiresAt, r.Signature
	next.Candidates = append([]nat.EndpointCandidate(nil), previous.Candidates...)
	for i := range next.Candidates {
		next.Candidates[i].ObservedAt, next.Candidates[i].ExpiresAt = r.CandidateTimes[i][0], r.CandidateTimes[i][1]
	}
	if err := next.Verify(networkID, now); err != nil {
		return PeerRecord{}, err
	}
	if !next.Supersedes(previous) {
		return PeerRecord{}, ErrRecordSuperseded
	}
	return next, nil
}
