package app

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
)

// Initialize the persistent NKN identity before the first daemon connection.
// A core-only build can still exercise the local account wizard in tests.
func (n *Node) PrepareNKNIdentity() error {
	if usageSeed == nil {
		return nil
	}
	_, err := usageSeed(n.Keystore)
	return err
}

// Read-only identity preview. Setup never replaces an existing NKN seed.
func dashboardSetupInfo(node *Node) map[string]string {
	info := map[string]string{"device_id": node.Device.DeviceID(), "device_name": node.Config.Device.Name}
	if seed, err := node.Keystore.ReadSecret("nkn.seed"); err == nil && len(seed) == ed25519.SeedSize {
		public := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
		info["nkn_address"] = "nknguard." + hex.EncodeToString(public)
	}
	if runtime, err := node.State.LoadRuntime(); err == nil {
		info["virtual_ip"] = runtime.VirtualIP
	}
	return info
}

func dashboardAccountChangeHandler(node *Node, logins *loginThrottle) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !dashboardActionAllowed(r) {
			http.Error(w, "same-origin action required", 403)
			return
		}
		var request struct {
			Current  string `json:"current"`
			Username string `json:"username"`
			New      string `json:"new"`
		}
		if json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&request) != nil {
			http.Error(w, "账号信息格式不正确", 400)
			return
		}
		ok, retry := logins.verify(func() bool { return node.VerifyDashboardPassword(request.Current) })
		if retry > 0 {
			tooManyAttempts(w, retry)
			return
		}
		if !ok {
			http.Error(w, "当前密码不正确", 403)
			return
		}
		if err := node.ChangeDashboardAccount(request.Current, request.Username, request.New); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		w.WriteHeader(204)
	}
}
