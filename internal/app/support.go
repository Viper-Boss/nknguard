package app

import (
	"net/http"

	qrcode "github.com/skip2/go-qrcode"
)

// Public donation addresses copied from the owner's GenomeDock sponsor config.
// These are receiving addresses, never credentials or private keys.
var supportAddresses = map[string]string{
	"usdt": "TEwbANy1Mo3DFdT6CMphgjU511LzbCoQsm",
	"btc":  "bc1q8m5fp9jgmve8sjva2cfdwhs3pc65723nezrc3v",
	"eth":  "0x9d955292BD72904fB5D5D9A147250A625f80c6E5",
	"sol":  "24BL4HqrJUdDzg6fu3yk4Qi5oh6utRUWEQitpCa5HgwS",
}

func supportQRHandler() http.HandlerFunc {
	images := make(map[string][]byte, len(supportAddresses))
	for asset, address := range supportAddresses {
		images[asset], _ = qrcode.Encode(address, qrcode.Medium, 320)
	}
	return func(w http.ResponseWriter, r *http.Request) {
		image, ok := images[r.PathValue("asset")]
		if !ok || len(image) == 0 {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write(image)
	}
}
