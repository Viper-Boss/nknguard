// Command nknguard is a serverless WireGuard mesh over NKN.
//
//	nknguard init                        create a network and join it
//	nknguard join <network-id> --secret  join an existing network
//	nknguard invite                      print the join command for another device
//	sudo nknguard up                     run the daemon (foreground; use systemd for background)
//	sudo nknguard down                   stop the daemon and remove the interface
//	nknguard status | peers | doctor     inspect
//	nknguard diagnostics export          write a redacted bug-report bundle
package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"golang.org/x/term"

	"github.com/Viper-Boss/nknguard/internal/app"
	"github.com/Viper-Boss/nknguard/internal/config"
	"github.com/Viper-Boss/nknguard/pkg/diagnostics"
)

const usage = `nknguard — serverless WireGuard mesh over NKN

Usage:
  nknguard init [--name <device-name>]          create a network and set the dashboard password
  nknguard join <network-id> --secret <secret>  join an existing network
  nknguard invite                               print the command that joins another device
  nknguard pair <QR-content> [--name name]       request owner-approved enrollment
  nknguard client                               open the Windows connect/disconnect app
  nknguard leave                                forget the network (keeps the device identity)
  nknguard identity                             show this device's id
  nknguard dashboard-password set               set or change the dashboard password privately
  nknguard dashboard-key                        show a legacy generated password, if present
  sudo nknguard up                              run the daemon in the foreground
  sudo nknguard daemon                          same as up (what the systemd unit runs)
  sudo nknguard down                            stop the daemon and remove the interface
  sudo nknguard cleanup                         retry cleanup of a stopped daemon's tunnel
  nknguard status                               node and peer summary
  nknguard peers                                peer table with state history
  nknguard reconnect <device-id>                retry a direct path now
  nknguard doctor                               check this host and the running node
  nknguard diagnostics export [-o file]         redacted bundle for a bug report
  nknguard config                               print the effective configuration
  nknguard version

Global flags (before the command):
  --config <path>     configuration file (default /etc/nknguard/config.yaml)
  --state-dir <path>  override paths.state_dir
  --socket <path>     override paths.socket
`

type globals struct {
	configPath string
	stateDir   string
	socket     string
}

var guiBuild string

func main() {
	args := os.Args[1:]
	if runtime.GOOS == "windows" && guiBuild == "1" && len(args) == 0 {
		args = []string{"client"}
	}
	if runtime.GOOS == "windows" && guiBuild == "1" && len(args) > 0 && (args[len(args)-1] == "up" || args[len(args)-1] == "cleanup") {
		var diagnostic bytes.Buffer
		code := run(args, os.Stdout, io.MultiWriter(os.Stderr, &diagnostic))
		if code != 0 {
			path := filepath.Join(os.Getenv("LOCALAPPDATA"), "NKNGuard", "last-error.txt")
			_ = os.MkdirAll(filepath.Dir(path), 0o700)
			_ = os.WriteFile(path, diagnostic.Bytes(), 0o600)
		}
		os.Exit(code)
	}
	os.Exit(run(args, os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	var g globals
	top := flag.NewFlagSet("nknguard", flag.ContinueOnError)
	top.SetOutput(stderr)
	top.Usage = func() { fmt.Fprint(stderr, usage) }
	top.StringVar(&g.configPath, "config", config.DefaultConfigPath(), "")
	top.StringVar(&g.stateDir, "state-dir", "", "")
	top.StringVar(&g.socket, "socket", "", "")
	if err := top.Parse(args); err != nil {
		return 2
	}
	rest := top.Args()
	if len(rest) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	command, rest := rest[0], rest[1:]
	var err error
	switch command {
	case "init":
		err = cmdInit(g, rest, stdout, stderr)
	case "join":
		err = cmdJoin(g, rest, stdout)
	case "invite":
		err = cmdInvite(g, stdout)
	case "pair":
		err = cmdPair(g, rest, stdout)
	case "client":
		err = cmdClient(g, stdout)
	case "leave":
		err = cmdLeave(g, stdout)
	case "identity":
		err = cmdIdentity(g, stdout)
	case "dashboard-key":
		err = cmdDashboardKey(g, stdout)
	case "dashboard-password":
		err = cmdDashboardPassword(g, rest, stdout, stderr)
	case "up", "daemon":
		err = cmdUp(g, stderr)
	case "down":
		err = cmdDown(g, stdout)
	case "cleanup":
		var cfg config.Config
		cfg, _, err = loadConfig(g)
		if err == nil {
			err = app.CleanupStoppedTunnel(cfg)
		}
	case "status":
		err = cmdStatus(g, stdout)
	case "peers":
		err = cmdPeers(g, stdout)
	case "reconnect":
		err = cmdReconnect(g, rest, stdout)
	case "doctor":
		return cmdDoctor(g, stdout, stderr)
	case "diagnostics":
		err = cmdDiagnostics(g, rest, stdout)
	case "config":
		err = cmdConfig(g, stdout)
	case "version":
		nkn, dht := app.BuildFeatures()
		fmt.Fprintf(stdout, "nknguard %s (nkn=%t dht=%t)\n", app.Version, nkn, dht)
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n%s", command, usage)
		return 2
	}
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	return 0
}

// loadConfig reads the config file, falling back to defaults when it does not
// exist yet (before `init`).
func loadConfig(g globals) (config.Config, bool, error) {
	cfg, err := config.Load(g.configPath)
	exists := true
	if errors.Is(err, os.ErrNotExist) {
		cfg, err, exists = config.Default(), nil, false
	}
	if err != nil {
		return cfg, exists, err
	}
	if g.stateDir != "" {
		cfg.Paths.StateDir = g.stateDir
	}
	if g.socket != "" {
		cfg.Paths.Socket = g.socket
	}
	cfg.Paths.LegacySetupNote = filepath.Join(filepath.Dir(g.configPath), "first-run.txt")
	return cfg, exists, nil
}

// writeConfig saves the configuration with the network id filled in. It never
// overwrites an operator's file except to set network.id.
func writeConfig(g globals, cfg config.Config, networkID string) error {
	cfg.Network.ID = networkID
	if err := os.MkdirAll(filepath.Dir(g.configPath), 0o755); err != nil {
		return err
	}
	return os.WriteFile(g.configPath, []byte(cfg.Render()), 0o644)
}

func cmdInit(g globals, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("init", flag.ContinueOnError)
	name := flags.String("name", "", "device name")
	passwordStdin := flags.Bool("dashboard-password-stdin", false, "read password from standard input")
	passwordFile := flags.String("dashboard-password-file", "", "read password from an owner-only file")
	if err := flags.Parse(args); err != nil {
		return err
	}
	cfg, exists, err := loadConfig(g)
	if err != nil {
		return err
	}
	if exists && cfg.Network.ID != "" {
		return errors.New("network already initialized; use `nknguard dashboard-password set` to change the password")
	}
	if *name != "" {
		cfg.Device.Name = *name
	}
	password, err := readDashboardPassword(*passwordStdin, *passwordFile, stderr)
	if err != nil {
		return err
	}
	node, err := app.OpenNode(cfg)
	if err != nil {
		return err
	}
	if err := node.SetDashboardPassword(password); err != nil {
		return err
	}
	networkID, secret, err := node.CreateNetwork()
	if err != nil {
		return err
	}
	if err := writeConfig(g, cfg, networkID); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Network created.\n\nNetwork ID:\n  %s\n\n", networkID)
	if cfg.Pairing.ApprovalRequired {
		fmt.Fprintf(stdout, "Start the NAS with: sudo nknguard up\nOpen the local dashboard at http://%s/ to scan and approve new devices.\nDashboard user: admin\nDashboard password: chosen during setup\n", cfg.Dashboard.Listen)
	} else {
		fmt.Fprintf(stdout, "Legacy join secret (keep private):\n  %s\n\nOn another device:\n  nknguard join %s --secret %s\n", secret, networkID, secret)
	}
	return nil
}

func cmdDashboardKey(g globals, stdout io.Writer) error {
	cfg, _, err := loadConfig(g)
	if err != nil {
		return err
	}
	node, err := app.OpenNode(cfg)
	if err != nil {
		return err
	}
	key, err := node.DashboardKey()
	if errors.Is(err, os.ErrNotExist) {
		return errors.New("dashboard password cannot be displayed; use `nknguard dashboard-password set` to change it")
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Dashboard user: admin\nDashboard password: %s\n", key)
	return nil
}

func cmdDashboardPassword(g globals, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 || args[0] != "set" {
		return errors.New("usage: nknguard dashboard-password set [--stdin | --file PATH]")
	}
	flags := flag.NewFlagSet("dashboard-password set", flag.ContinueOnError)
	flags.SetOutput(stderr)
	fromStdin := flags.Bool("stdin", false, "read password from standard input")
	file := flags.String("file", "", "read password from an owner-only file")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected dashboard-password argument")
	}
	password, err := readDashboardPassword(*fromStdin, *file, stderr)
	if err != nil {
		return err
	}
	cfg, _, err := loadConfig(g)
	if err != nil {
		return err
	}
	node, err := app.OpenNode(cfg)
	if err != nil {
		return err
	}
	// SetDashboardPassword also removes the legacy first-run.txt that older
	// installers wrote with the generated password.
	if err := node.SetDashboardPassword(password); err != nil {
		return err
	}
	fmt.Fprintln(stdout, "Dashboard password updated. Sign in with the new password; no service restart is needed.")
	return nil
}

func readDashboardPassword(fromStdin bool, file string, stderr io.Writer) (string, error) {
	if fromStdin && file != "" {
		return "", errors.New("choose either --stdin or --file")
	}
	var password string
	switch {
	case file != "":
		info, err := os.Stat(file)
		if err != nil {
			return "", err
		}
		if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
			return "", errors.New("dashboard password file must be readable only by its owner")
		}
		data, err := os.ReadFile(file)
		if err != nil {
			return "", err
		}
		password = strings.TrimSuffix(strings.TrimSuffix(string(data), "\n"), "\r")
	case fromStdin:
		line, err := bufio.NewReader(io.LimitReader(os.Stdin, 1024)).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return "", err
		}
		password = strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
	default:
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			return "", errors.New("interactive terminal required; use --stdin or --file for automated setup")
		}
		fmt.Fprint(stderr, "Set dashboard password (at least 12 characters): ")
		first, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(stderr)
		if err != nil {
			return "", err
		}
		fmt.Fprint(stderr, "Confirm dashboard password: ")
		second, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(stderr)
		if err != nil {
			return "", err
		}
		if !bytes.Equal(first, second) {
			return "", errors.New("dashboard passwords do not match")
		}
		password = string(first)
	}
	if err := app.ValidateDashboardPassword(password); err != nil {
		return "", err
	}
	return password, nil
}

func cmdJoin(g globals, args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("join", flag.ContinueOnError)
	secret := flags.String("secret", "", "join secret")
	name := flags.String("name", "", "device name")
	// Accept `join <id> --secret x` as well as `join --secret x <id>`.
	var networkID string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		networkID, args = args[0], args[1:]
	}
	if err := flags.Parse(args); err != nil {
		return err
	}
	if networkID == "" && flags.NArg() > 0 {
		networkID = flags.Arg(0)
	}
	if networkID == "" || *secret == "" {
		return errors.New("usage: nknguard join <network-id> --secret <secret>")
	}
	cfg, _, err := loadConfig(g)
	if err != nil {
		return err
	}
	if *name != "" {
		cfg.Device.Name = *name
	}
	if cfg.Pairing.ApprovalRequired {
		return errors.New("pairing approval is enabled; use `nknguard pair <QR-content>` and approve on the NAS dashboard")
	}
	node, err := app.OpenNode(cfg)
	if err != nil {
		return err
	}
	if err := node.Join(networkID, *secret); err != nil {
		return err
	}
	if err := writeConfig(g, cfg, networkID); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Joined %s as %s (%s).\nStart the node with: sudo nknguard up\n", networkID, cfg.Device.Name, node.Device.DeviceID())
	return nil
}

func cmdInvite(g globals, stdout io.Writer) error {
	cfg, _, err := loadConfig(g)
	if err != nil {
		return err
	}
	if cfg.Pairing.ApprovalRequired {
		return errors.New("pairing approval is enabled; generate a one-time QR invitation in the NAS dashboard")
	}
	node, err := app.OpenNode(cfg)
	if err != nil {
		return err
	}
	_, current, err := node.MembershipKey()
	if err != nil {
		return err
	}
	secret, err := node.JoinSecret()
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "nknguard join %s --secret %s\n", current.NetworkID, secret)
	return nil
}

func cmdPair(g globals, args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("pair", flag.ContinueOnError)
	name := flags.String("name", "", "device name")
	var invitation string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		invitation, args = args[0], args[1:]
	}
	if err := flags.Parse(args); err != nil {
		return err
	}
	if invitation == "" && flags.NArg() > 0 {
		invitation = flags.Arg(0)
	}
	if invitation == "" {
		return errors.New("usage: nknguard pair <QR-content> [--name name]")
	}
	cfg, _, err := loadConfig(g)
	if err != nil {
		return err
	}
	if *name != "" {
		cfg.Device.Name = *name
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	result, err := app.PairDevice(ctx, cfg, invitation, stdout)
	if err != nil {
		return err
	}
	cfg.Discovery.StaticPeers = append(cfg.Discovery.StaticPeers, result.NASAddress)
	if err := writeConfig(g, cfg, result.NetworkID); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "已获 NAS 授权。NAS ID：%s。现在可以启动客户端连接。\n", result.NASID)
	return nil
}

func cmdLeave(g globals, stdout io.Writer) error {
	cfg, _, err := loadConfig(g)
	if err != nil {
		return err
	}
	node, err := app.OpenNode(cfg)
	if err != nil {
		return err
	}
	if err := node.Leave(); err != nil {
		return err
	}
	fmt.Fprintln(stdout, "Left the network. The device identity is kept.")
	return nil
}

func cmdIdentity(g globals, stdout io.Writer) error {
	cfg, _, err := loadConfig(g)
	if err != nil {
		return err
	}
	node, err := app.OpenNode(cfg)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Device:    %s\nDevice ID: %s\n", cfg.Device.Name, node.Device.DeviceID())
	if _, current, err := node.MembershipKey(); err == nil {
		fmt.Fprintf(stdout, "Network:   %s\n", current.NetworkID)
	}
	return nil
}

func cmdUp(g globals, stderr io.Writer) error {
	cfg, exists, err := loadConfig(g)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("%s does not exist — run `nknguard init` or `nknguard join` first", g.configPath)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return app.RunDaemon(ctx, cfg, stderr)
}

func client(g globals) (*app.Client, error) {
	cfg, _, err := loadConfig(g)
	if err != nil {
		return nil, err
	}
	return app.NewClient(cfg.Paths.Socket), nil
}

func cmdDown(g globals, stdout io.Writer) error {
	c, err := client(g)
	if err != nil {
		return err
	}
	if err := c.Down(); err != nil {
		return err
	}
	fmt.Fprintln(stdout, "Stopping; the interface is removed when the daemon exits.")
	return nil
}

func cmdStatus(g globals, stdout io.Writer) error {
	c, err := client(g)
	if err != nil {
		return err
	}
	status, err := c.Status()
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "NKNGuard %s\n\nNetwork:    %s\nDevice:     %s (%s)\nVirtual IP: %s\nNAT:        %s\nUptime:     %s\n\n",
		status.Version, status.NetworkID, status.Device, status.DeviceID, status.VirtualIP, status.NAT, status.Uptime)
	printPeers(stdout, status)
	m := status.Metrics
	fmt.Fprintf(stdout, "\npeers=%d direct=%d relay=%d punch_ok=%d punch_fail=%d relay_fallbacks=%d path_switches=%d rejected_records=%d rejected_msgs=%d\n",
		m.PeersTotal, m.PeersDirect, m.PeersRelay, m.PunchSuccess, m.PunchFailure, m.RelayFallbacks, m.PathSwitches, m.RecordsRejected, m.EnvelopesRejected)
	return nil
}

func printPeers(stdout io.Writer, status diagnostics.Status) {
	if len(status.Peers) == 0 {
		fmt.Fprintln(stdout, "No peers yet.")
		return
	}
	peers := status.Peers
	sort.Slice(peers, func(i, j int) bool { return peers[i].Name < peers[j].Name })
	table := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(table, "PEER\tIP\tPATH\tSTATE\tENDPOINT\tLAST HANDSHAKE")
	for _, peer := range peers {
		name := peer.Name
		if name == "" {
			name = peer.DeviceID
		}
		handshake := "-"
		if !peer.LastHandshake.IsZero() {
			handshake = time.Since(peer.LastHandshake).Round(time.Second).String() + " ago"
		}
		fmt.Fprintf(table, "%s\t%s\t%s\t%s\t%s\t%s\n", name, peer.VirtualIP, peer.Path, peer.State, dash(peer.Endpoint), handshake)
	}
	_ = table.Flush()
}

func dash(value string) string {
	if value == "" {
		return "-"
	}
	return value
}

func cmdPeers(g globals, stdout io.Writer) error {
	c, err := client(g)
	if err != nil {
		return err
	}
	peers, err := c.Peers()
	if err != nil {
		return err
	}
	for _, peer := range peers {
		fmt.Fprintf(stdout, "%s  %s\n  state=%s path=%s ip=%s endpoint=%s\n  wireguard=%s\n  nkn=%s\n",
			peer.Name, peer.DeviceID, peer.State, peer.Path, peer.VirtualIP, dash(peer.Endpoint), peer.WireGuardPublicKey, peer.NKNAddress)
		if peer.LastError != "" {
			fmt.Fprintf(stdout, "  last error: %s\n", peer.LastError)
		}
		for _, step := range peer.History {
			fmt.Fprintf(stdout, "    %s  %s -> %s (%s)\n", step.At.Format("15:04:05"), step.From, step.To, step.Event)
		}
		fmt.Fprintln(stdout)
	}
	if len(peers) == 0 {
		fmt.Fprintln(stdout, "No peers yet.")
	}
	return nil
}

func cmdReconnect(g globals, args []string, stdout io.Writer) error {
	if len(args) != 1 {
		return errors.New("usage: nknguard reconnect <device-id>")
	}
	c, err := client(g)
	if err != nil {
		return err
	}
	if err := c.Reconnect(args[0]); err != nil {
		return err
	}
	fmt.Fprintln(stdout, "Direct attempt scheduled.")
	return nil
}

func cmdDoctor(g globals, stdout, stderr io.Writer) int {
	cfg, _, err := loadConfig(g)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	report := app.Doctor(ctx, cfg)
	for _, check := range report.Checks {
		line := fmt.Sprintf("[%-4s] %s", check.Level, check.Name)
		if check.Detail != "" {
			line += " — " + check.Detail
		}
		fmt.Fprintln(stdout, line)
	}
	if report.Worst() == diagnostics.LevelFail {
		return 1
	}
	return 0
}

func cmdDiagnostics(g globals, args []string, stdout io.Writer) error {
	if len(args) == 0 || args[0] != "export" {
		return errors.New("usage: nknguard diagnostics export [-o file]")
	}
	flags := flag.NewFlagSet("diagnostics", flag.ContinueOnError)
	output := flags.String("o", fmt.Sprintf("nknguard-diagnostics-%s.tar.gz", time.Now().Format("20060102-150405")), "output file")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	cfg, _, err := loadConfig(g)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(*output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if err := app.ExportDiagnostics(cfg, file); err != nil {
		_ = file.Close()
		_ = os.Remove(*output)
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Wrote %s (keys and secrets redacted).\n", *output)
	return nil
}

func cmdConfig(g globals, stdout io.Writer) error {
	cfg, _, err := loadConfig(g)
	if err != nil {
		return err
	}
	fmt.Fprint(stdout, cfg.Render())
	return nil
}
