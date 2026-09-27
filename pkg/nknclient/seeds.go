package nknclient

import "strings"

// ChinaSeedRPC lists community-operated NKN seed RPC servers in mainland
// China. The official seeds all resolve overseas (checked 2026-09-08: eight
// addresses in SG/US/NL/GB/DE/CA/IN) and are slow or unreachable from many
// Chinese networks, so without a domestic seed a NAS or phone in China often
// cannot reach the NKN network at all.
//
// The list is taken from NasSimHub (internal/httpapi/homesim_forward_nkn.go,
// verified there with a JSON-RPC probe on 2026-09-08, ~95 ms from Shanghai).
// Community addresses drift; refresh with NasSimHub's
// dev/collect_nkn_cn_nodes.py before editing.
var ChinaSeedRPC = []string{
	"http://183.53.109.45:30003", // Chinanet
}

// OfficialSeedRPC mirrors nkn-sdk-go v1.4.8 DefaultSeedRPCServerAddr.
var OfficialSeedRPC = []string{
	"http://seed.nkn.org:30003",
	"http://mainnet-seed-0001.nkn.org:30003",
	"http://mainnet-seed-0002.nkn.org:30003",
	"http://mainnet-seed-0003.nkn.org:30003",
	"http://mainnet-seed-0004.nkn.org:30003",
	"http://mainnet-seed-0005.nkn.org:30003",
	"http://mainnet-seed-0006.nkn.org:30003",
	"http://mainnet-seed-0007.nkn.org:30003",
	"http://mainnet-seed-0008.nkn.org:30003",
}

// SeedRPCList returns the seed RPC servers in the order they are tried:
// operator-configured seeds (nkn.seed_rpc, e.g. a self-hosted node), then the
// built-in China seeds, then the official seeds. nkn-sdk-go tries them one at
// a time in list order (RPCConcurrency 1, 10 s each) and uses the first that
// answers, so a dead configured or community seed only costs its timeout and
// the official seeds always remain as a fallback. Duplicates are dropped.
func SeedRPCList(configured []string) []string {
	out := make([]string, 0, len(configured)+len(ChinaSeedRPC)+len(OfficialSeedRPC))
	seen := make(map[string]bool)
	for _, group := range [][]string{configured, ChinaSeedRPC, OfficialSeedRPC} {
		for _, value := range group {
			value = strings.TrimSpace(value)
			if value == "" || seen[value] {
				continue
			}
			seen[value] = true
			out = append(out, value)
		}
	}
	return out
}
