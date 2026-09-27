//go:build windows

package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/Viper-Boss/nknguard/internal/app"
	"github.com/Viper-Boss/nknguard/internal/state"
	"github.com/Viper-Boss/nknguard/pkg/mesh"
)

//go:embed clientui/*
var clientAssets embed.FS

type clientWindow struct {
	mu           sync.Mutex
	globals      globals
	pairing      bool
	connecting   bool
	connectSince time.Time
	message      string
	pairCode     string
	nasAddress   string
	errorMessage string
}

func (w *clientWindow) update(fn func()) {
	w.mu.Lock()
	defer w.mu.Unlock()
	fn()
}

func (w *clientWindow) snapshot() map[string]any {
	w.mu.Lock()
	pairing, connecting, connectSince, message, pairCode, nasAddress, errorMessage :=
		w.pairing, w.connecting, w.connectSince, w.message, w.pairCode, w.nasAddress, w.errorMessage
	w.mu.Unlock()
	cfg, _, err := loadConfig(w.globals)
	result := map[string]any{
		"paired": false, "connected": false, "pairing": pairing,
		"connecting": connecting, "message": message,
		"pair_code": pairCode, "nas_address": nasAddress,
		"error": errorMessage, "path": "none",
	}
	if err != nil {
		result["error"] = err.Error()
		return result
	}
	current, err := state.New(cfg.Paths.StateDir).LoadMembership()
	if err == nil && current.NetworkID != "" {
		result["paired"] = true
		result["device_id"] = current.DeviceID
		result["network_id"] = current.NetworkID
		if len(cfg.Discovery.StaticPeers) > 0 {
			result["nas_address"] = cfg.Discovery.StaticPeers[0]
		}
	}
	status, err := app.NewClient(cfg.Paths.Socket).Status()
	if err == nil {
		w.update(func() { w.connecting = false })
		result["connected"] = true
		result["connecting"] = false
		result["local_nkn_address"] = status.NKNAddress
		result["virtual_ip"] = status.VirtualIP
		result["wireguard_state"] = status.WireGuard.State
		for _, peer := range status.Peers {
			if peer.Path == mesh.PathDirectWG || peer.Path == mesh.PathNKNRelay {
				result["path"] = peer.Path
				result["nas_address"] = peer.NKNAddress
				result["nas_ip"] = peer.VirtualIP
				break
			}
		}
	} else if connecting {
		errorPath := filepath.Join(os.Getenv("LOCALAPPDATA"), "NKNGuard", "last-error.txt")
		if raw, readErr := os.ReadFile(errorPath); readErr == nil && len(raw) > 0 {
			w.update(func() { w.connecting = false; w.errorMessage = strings.TrimSpace(string(raw)) })
			result["connecting"] = false
			result["error"] = strings.TrimSpace(string(raw))
		} else if time.Since(connectSince) > 45*time.Second {
			message := "连接超时；请确认已安装 WireGuard，并检查 Windows 管理员授权"
			w.update(func() { w.connecting = false; w.errorMessage = message })
			result["connecting"] = false
			result["error"] = message
		}
	}
	return result
}

type pairProgress struct{ window *clientWindow }

var codePattern = regexp.MustCompile("验证码 ([0-9]{6})")

func (p pairProgress) Write(raw []byte) (int, error) {
	message := strings.TrimSpace(string(raw))
	p.window.update(func() {
		p.window.message = message
		if matched := codePattern.FindStringSubmatch(message); len(matched) == 2 {
			p.window.pairCode = matched[1]
		}
	})
	return len(raw), nil
}

func (w *clientWindow) pair(invitation, name string) error {
	invite, err := app.ParsePairInvite(invitation)
	if err != nil {
		return err
	}
	cfg, _, err := loadConfig(w.globals)
	if err != nil {
		return err
	}
	current, err := state.New(cfg.Paths.StateDir).LoadMembership()
	if err != nil {
		return err
	}
	if current.NetworkID != "" {
		return errors.New("这台电脑已经配对；请先断开原有网络")
	}
	if name != "" {
		cfg.Device.Name = name
	}
	w.mu.Lock()
	if w.pairing {
		w.mu.Unlock()
		return errors.New("已有配对申请正在进行")
	}
	w.pairing = true
	w.pairCode = ""
	w.nasAddress = invite.NASAddress
	w.errorMessage = ""
	w.message = "正在向 NAS 发送配对申请…"
	w.mu.Unlock()
	go func() {
		ctx, cancel := context.WithDeadline(context.Background(), invite.ExpiresAt)
		defer cancel()
		result, err := app.PairDevice(ctx, cfg, invitation, pairProgress{window: w})
		if err == nil {
			cfg.Discovery.StaticPeers = append(cfg.Discovery.StaticPeers, result.NASAddress)
			err = writeConfig(w.globals, cfg, result.NetworkID)
		}
		w.update(func() {
			w.pairing = false
			if err != nil {
				w.errorMessage = err.Error()
				w.message = "配对未完成"
			} else {
				w.message = "NAS 已批准，可以连接"
				w.pairCode = ""
				w.nasAddress = result.NASAddress
			}
		})
	}()
	return nil
}

func runElevated(executable, configPath string) error {
	verb, _ := syscall.UTF16PtrFromString("runas")
	file, err := syscall.UTF16PtrFromString(executable)
	if err != nil {
		return err
	}
	params, err := syscall.UTF16PtrFromString("--config " + syscall.EscapeArg(configPath) + " up")
	if err != nil {
		return err
	}
	shell := syscall.NewLazyDLL("shell32.dll").NewProc("ShellExecuteW")
	result, _, callErr := shell.Call(0, uintptr(unsafe.Pointer(verb)), uintptr(unsafe.Pointer(file)), uintptr(unsafe.Pointer(params)), 0, 1)
	if result <= 32 {
		return fmt.Errorf("管理员授权未完成: %v", callErr)
	}
	return nil
}

func (w *clientWindow) connect() error {
	cfg, _, err := loadConfig(w.globals)
	if err != nil {
		return err
	}
	current, err := state.New(cfg.Paths.StateDir).LoadMembership()
	if err != nil || current.NetworkID == "" {
		return errors.New("请先完成 NAS 配对")
	}
	if _, err := app.NewClient(cfg.Paths.Socket).Status(); err == nil {
		return nil
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	w.update(func() {
		w.connecting = true
		w.connectSince = time.Now()
		w.errorMessage = ""
		w.message = "正在请求管理员权限并建立连接…"
	})
	_ = os.Remove(filepath.Join(os.Getenv("LOCALAPPDATA"), "NKNGuard", "last-error.txt"))
	if err := runElevated(executable, w.globals.configPath); err != nil {
		w.update(func() { w.connecting = false; w.errorMessage = err.Error() })
		return err
	}
	return nil
}

func (w *clientWindow) disconnect() error {
	cfg, _, err := loadConfig(w.globals)
	if err != nil {
		return err
	}
	err = app.NewClient(cfg.Paths.Socket).Down()
	if errors.Is(err, app.ErrDaemonNotRunning) {
		err = nil
	}
	if err == nil {
		w.update(func() { w.connecting = false; w.message = "已断开"; w.errorMessage = "" })
	}
	return err
}

func (w *clientWindow) routes(done chan<- struct{}) http.Handler {
	assets, _ := fs.Sub(clientAssets, "clientui")
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/state", func(out http.ResponseWriter, _ *http.Request) {
		out.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(out).Encode(w.snapshot())
	})
	mux.HandleFunc("POST /api/pair", func(out http.ResponseWriter, r *http.Request) {
		var input map[string]string
		if err := json.NewDecoder(io.LimitReader(r.Body, 8192)).Decode(&input); err != nil {
			http.Error(out, "配对内容无效", http.StatusBadRequest)
			return
		}
		if err := w.pair(input["invitation"], input["name"]); err != nil {
			http.Error(out, err.Error(), http.StatusBadRequest)
			return
		}
		out.WriteHeader(http.StatusAccepted)
	})
	mux.HandleFunc("POST /api/connect", func(out http.ResponseWriter, _ *http.Request) {
		if err := w.connect(); err != nil {
			http.Error(out, err.Error(), http.StatusBadRequest)
			return
		}
		out.WriteHeader(http.StatusAccepted)
	})
	mux.HandleFunc("POST /api/disconnect", func(out http.ResponseWriter, _ *http.Request) {
		if err := w.disconnect(); err != nil {
			http.Error(out, err.Error(), http.StatusBadRequest)
			return
		}
		out.WriteHeader(http.StatusAccepted)
	})
	mux.HandleFunc("POST /api/quit", func(out http.ResponseWriter, _ *http.Request) {
		out.WriteHeader(http.StatusAccepted)
		go func() { done <- struct{}{} }()
	})
	mux.Handle("/", http.FileServer(http.FS(assets)))
	return mux
}

func (w *clientWindow) serve(token string, done chan<- struct{}) http.Handler {
	next := w.routes(done)
	return http.HandlerFunc(func(out http.ResponseWriter, r *http.Request) {
		if host, _, err := net.SplitHostPort(r.Host); err != nil || host != "127.0.0.1" {
			http.Error(out, "loopback host required", http.StatusForbidden)
			return
		}
		out.Header().Set("Cache-Control", "no-store")
		out.Header().Set("X-Content-Type-Options", "nosniff")
		out.Header().Set("Content-Security-Policy", "default-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'")
		if supplied := r.URL.Query().Get("token"); supplied != "" && subtle.ConstantTimeCompare([]byte(supplied), []byte(token)) == 1 {
			http.SetCookie(out, &http.Cookie{Name: "nkg-client", Value: token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
			http.Redirect(out, r, "/", http.StatusSeeOther)
			return
		}
		cookie, err := r.Cookie("nkg-client")
		if err != nil || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(token)) != 1 {
			http.Error(out, "client session required", http.StatusUnauthorized)
			return
		}
		if r.Method == http.MethodPost && (r.Header.Get("X-NKNGuard-Client") != "1" || r.Header.Get("Origin") != "http://"+r.Host) {
			http.Error(out, "same-origin action required", http.StatusForbidden)
			return
		}
		next.ServeHTTP(out, r)
	})
}

func edgeExecutable() (string, error) {
	for _, base := range []string{os.Getenv("ProgramFiles(x86)"), os.Getenv("ProgramFiles")} {
		path := filepath.Join(base, "Microsoft", "Edge", "Application", "msedge.exe")
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}
	return exec.LookPath("msedge.exe")
}

func cmdClient(g globals, _ io.Writer) error {
	edge, err := edgeExecutable()
	if err != nil {
		return errors.New("Windows 客户端需要 Microsoft Edge")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer listener.Close()
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return err
	}
	token := base64.RawURLEncoding.EncodeToString(secret)
	window := &clientWindow{globals: g}
	done := make(chan struct{}, 1)
	server := &http.Server{Handler: window.serve(token, done), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = server.Serve(listener) }()
	defer server.Close()
	profile, err := os.MkdirTemp("", "nknguard-client-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(profile)
	url := "http://" + listener.Addr().String() + "/?token=" + token
	edgeProcess := exec.Command(edge, "--app="+url, "--user-data-dir="+profile)
	if err := edgeProcess.Start(); err != nil {
		return err
	}
	exited := make(chan struct{})
	go func() { _ = edgeProcess.Wait(); close(exited) }()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	select {
	case <-done:
	case <-exited:
	case <-ctx.Done():
	}
	_ = window.disconnect()
	return nil
}
