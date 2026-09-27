//go:build !nknsdk

package usagestats

// NewNKNChain reports that this build has no NKN support; the reporter then
// sends nothing and shows the counts as unavailable.
func NewNKNChain(nknSeed []byte, seedRPC []string) (Chain, error) {
	return nil, ErrUnavailable
}
