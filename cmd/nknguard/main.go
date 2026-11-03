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
  --dashboard-listen <IP:port|auto-lan:port>  override dashboard listener
`

type globals struct {
	configPath      string
	stateDir        string
	socket          string
	dashboardListen string
}

var guiBuild string

func main() {
	args := os.Args[1:]
	if runtime.GOOS == "windows" && guiBuild == "1" && len(args) == 0 {
		args = []string{"client"}
	}
	if runtime.GOOS == "windows" && guiBuild == "1" && len(args) > 0 && (args[len(args)-1] == "up" || args[len(args)-1] == "cleanup" || args[len(args)-1] == "install-wireguard") {
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
	top.StringVar(&g.dashboardListen, "dashboard-listen", "", "")
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
	case "install-wireguard":
		err = installWireGuardDependency()
	case "update-check":
		err = cmdUpdateCheck(stdout)
	case "update-apply":
		var cfg config.Config
		cfg, _, err = loadConfig(g)
		if err == nil && len(rest) == 1 {
			err = app.ApplyUpdate(cfg, rest[0])
		} else if err == nil {
			err = errors.New("update-apply requires a staged job directory")
		}
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
	if g.dashboardListen != "" {
		cfg.Dashboard.Listen, err = resolveDashboardListen(g.dashboardListen)
		if err != nil {
			return cfg, exists, err
		}
	}
	cfg.SourceFile, err = filepath.Abs(g.configPath)
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
	username := flags.String("dashboard-user", "", "administrator username")
	deferSetup := flags.Bool("defer-dashboard-setup", false, "choose administrator credentials in the first-run web wizard")
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
	var password string
	if *deferSetup {
		if *passwordStdin || *passwordFile != "" || *username != "" {
			return errors.New("web setup cannot be combined with credential flags")
		}
	} else {
		if *username == "" {
			*username = "admin"
			if !*passwordStdin && *passwordFile == "" && term.IsTerminal(int(os.Stdin.Fd())) {
				fmt.Fprint(stderr, "Set dashboard username (3–32 characters): ")
				line, err := bufio.NewReader(io.LimitReader(os.Stdin, 256)).ReadString('\n')
				if err != nil {
					return err
				}
				*username = strings.TrimSpace(line)
			}
		}
		if err := app.ValidateDashboardUsername(*username); err != nil {
			return err
		}
		password, err = readDashboardPassword(*passwordStdin, *passwordFile, stderr)
		if err != nil {
			return err
		}
	}
	node, err := app.OpenNode(cfg)
	if err != nil {
		return err
	}
	if !*deferSetup {
		if err := node.SetupDashboardAccount(*username, password); err != nil {
			return err
		}
	}
	if err := node.PrepareNKNIdentity(); err != nil {
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
		fmt.Fprintf(stdout, "Start the NAS with: sudo nknguard up\nOpen the local dashboard at http://%s/ to finish setup and approve devices.\n", cfg.Dashboard.Listen)
		if !*deferSetup {
			fmt.Fprintf(stdout, "Dashboard user: %s\nDashboard password: chosen during setup\n", *username)
		}
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
	username := flags.String("username", "", "also change the administrator username")
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
	if *username != "" {
		err = node.SetDashboardAccount(*username, password)
	} else {
		err = node.SetDashboardPassword(password)
	}
	if err != nil {
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
		fmt.Fprintf(table, "%s\t%s\t%s\t%s\t%s\t%s\n",…5825 tokens truncated…/blake256 v1.1.0/go.mod h1:2OfgNZ5wDpcsFmHmCK5gZTPcCXqlm2ArzUIkw9czNJo=
github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.1 h1:5RVFMOWjMyRy8cARdy79nAmgYw3hK/4HUq48LQ6Wwqo=
github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.1/go.mod h1:ZXNYxsqcloTdSy/rNShjYzMhyjf0LaoftYK0p+A3h40=
github.com/dunglas/httpsfv v1.1.0 h1:Jw76nAyKWKZKFrpMMcL76y35tOpYHqQPzHQiwDvpe54=
github.com/dunglas/httpsfv v1.1.0/go.mod h1:zID2mqw9mFsnt7YC3vYQ9/cjq30q41W+1AnDwH8TiMg=
github.com/filecoin-project/go-clock v0.1.0 h1:SFbYIM75M8NnFm1yMHhN9Ahy3W5bEZV9gd6MPfXbKVU=
github.com/filecoin-project/go-clock v0.1.0/go.mod h1:4uB/O4PvOjlx1VCMdZ9MyDZXRm//gkj1ELEbxfI1AZs=
github.com/flynn/noise v1.1.0 h1:KjPQoQCEFdZDiP03phOvGi11+SVVhBG2wOWAorLsstg=
github.com/flynn/noise v1.1.0/go.mod h1:xbMo+0i6+IGbYdJhF31t2eR1BIU0CYc12+BNAKwUTag=
github.com/frankban/quicktest v1.14.6 h1:7Xjx+VpznH+oBnejlPUj8oUpdxnVs4f8XU8WnHkI4W8=
github.com/frankban/quicktest v1.14.6/go.mod h1:4ptaffx2x8+WTWXmUCuVU6aPUX1/Mz7zb5vbUoiM6w0=
github.com/go-logr/logr v1.2.2/go.mod h1:jdQByPbusPIv2/zmleS9BjJVeZ6kBagPoEUsqbVz/1A=
github.com/go-logr/logr v1.4.3 h1:CjnDlHq8ikf6E492q6eKboGOC0T8CDaOvkHCIg8idEI=
github.com/go-logr/logr v1.4.3/go.mod h1:9T104GzyrTigFIr8wt5mBrctHMim0Nb2HLGrmQ40KvY=
github.com/go-logr/stdr v1.2.2 h1:hSWxHoqTgW2S2qGc0LTAI563KZ5YKYRhT3MFKZMbjag=
github.com/go-logr/stdr v1.2.2/go.mod h1:mMo/vtBO5dYbehREoey6XUKy/eSumjCCveDpRre4VKE=
github.com/golang/protobuf v1.4.0-rc.1/go.mod h1:ceaxUfeHdC40wWswd/P6IGgMaK3YpKi5j83Wpe3EHw8=
github.com/golang/protobuf v1.4.0-rc.1.0.20200221234624-67d41d38c208/go.mod h1:xKAWHe0F5eneWXFV3EuXVDTCmh+JuBKY0li0aMyXATA=
github.com/golang/protobuf v1.4.0-rc.2/go.mod h1:LlEzMj4AhA7rCAGe4KMBDvJI+AwstrUpVNzEA03Pprs=
github.com/golang/protobuf v1.4.0-rc.4.0.20200313231945-b860323f09d0/go.mod h1:WU3c8KckQ9AFe+yFwt9sWVRKCVIyN9cPHBJSNnbL67w=
github.com/golang/protobuf v1.4.0/go.mod h1:jodUvKwWbYaEsadDk5Fwe5c77LiNKVO9IDvqG2KuDX0=
github.com/golang/protobuf v1.4.1/go.mod h1:U8fpvMrcmy5pZrNK1lt4xCsGvpyWQ/VVv6QDs8UjoX8=
github.com/golang/protobuf v1.5.0/go.mod h1:FsONVRAS9T7sI+LIUmWTfcYkHO4aIWwzhcaSAoJOfIk=
github.com/golang/protobuf v1.5.2 h1:ROPKBNFfQgOUMifHyP+KYbvpjbdoFNs+aK7DXlji0Tw=
github.com/golang/protobuf v1.5.2/go.mod h1:XVQd3VNwM+JqD3oG2Ue2ip4fOMUkwXdXDdiuN0vRsmY=
github.com/google/btree v1.1.2 h1:xf4v41cLI2Z6FxbKm+8Bu+m8ifhj15JuZ9sa0jZCMUU=
github.com/google/btree v1.1.2/go.mod h1:qOPhT0dTNdNzV6Z/lhRX0YXUafgPLFUh+gZMl761Gm4=
github.com/google/go-cmp v0.3.0/go.mod h1:8QqcDgzrUqlUb/G2PQTWiueGozuR1884gddMywk6iLU=
github.com/google/go-cmp v0.3.1/go.mod h1:8QqcDgzrUqlUb/G2PQTWiueGozuR1884gddMywk6iLU=
github.com/google/go-cmp v0.4.0/go.mod h1:v8dTdLbMG2kIc/vJvl+f65V22dbkXbowE6jgT/gNBxE=
github.com/google/go-cmp v0.5.5/go.mod h1:v8dTdLbMG2kIc/vJvl+f65V22dbkXbowE6jgT/gNBxE=
github.com/google/go-cmp v0.7.0 h1:wk8382ETsv4JYUZwIsn6YpYiWiBsYLSJiTsyBybVuN8=
github.com/google/go-cmp v0.7.0/go.mod h1:pXiqmnSA92OHEEa9HXL2W4E7lf9JzCmGVUdgjX3N/iU=
github.com/google/gopacket v1.1.19 h1:ves8RnFZPGiFnTS0uPQStjwru6uO6h+nlr9j6fL7kF8=
github.com/google/gopacket v1.1.19/go.mod h1:iJ8V8n6KS+z2U1A8pUwu8bW5SyEMkXJB8Yo/Vo+TKTo=
github.com/google/uuid v1.0.0/go.mod h1:TIyPZe4MgqvfeYDBFedMoGGpEw/LqOeaOT+nhxU+yHo=
github.com/google/uuid v1.6.0 h1:NIvaJDMOsjHA8n1jAhLSgzrAzy1Hgr+hNrb57e+94F0=
github.com/google/uuid v1.6.0/go.mod h1:TIyPZe4MgqvfeYDBFedMoGGpEw/LqOeaOT+nhxU+yHo=
github.com/gopherjs/gopherjs v1.17.2 h1:fQnZVsXk8uxXIStYb0N4bGk7jeyTalG/wsZjQ25dO0g=
github.com/gopherjs/gopherjs v1.17.2/go.mod h1:pRRIvn/QzFLrKfvEz3qUuEhtE/zLCWfreZ6J5gM2i+k=
github.com/gorilla/websocket v1.5.3 h1:saDtZ6Pbx/0u+bgYQ3q96pZgCzfhKXGPqt7kZ72aNNg=
github.com/gorilla/websocket v1.5.3/go.mod h1:YR8l580nyteQvAITg2hZ9XVh4b55+EU/adAjf1fMHhE=
github.com/hashicorp/errwrap v1.0.0 h1:hLrqtEDnRye3+sgx6z4qVLNuviH3MR5aQ0ykNJa/UYA=
github.com/hashicorp/errwrap v1.0.0/go.mod h1:YH+1FKiLXxHSkmPseP+kNlulaMuP3n2brvKWEqk/Jc4=
github.com/hashicorp/go-multierror v1.0.0 h1:iVjPR7a6H0tWELX5NxNe7bYopibicUzc7uPribsnS6o=
github.com/hashicorp/go-multierror v1.0.0/go.mod h1:dHtQlpGsu+cZNNAkkCN/P3hoUDHhCYQXV3UM06sGGrk=
github.com/hashicorp/golang-lru v1.0.2 h1:dV3g9Z/unq5DpblPpw+Oqcv4dU/1omnb4Ok8iPY6p1c=
github.com/hashicorp/golang-lru v1.0.2/go.mod h1:iADmTwqILo4mZ8BN3D2Q6+9jd8WM5uGBxy+E8yxSoD4=
github.com/huin/goupnp v1.3.0 h1:UvLUlWDNpoUdYzb2TCn+MuTWtcjXKSza2n6CBdQ0xXc=
github.com/huin/goupnp v1.3.0/go.mod h1:gnGPsThkYa7bFi/KWmEysQRf48l2dvR5bxr2OFckNX8=
github.com/imdario/mergo v0.3.8/go.mod h1:2EnlNZ0deacrJVfApfmtdGgDfMuh/nq6Ok1EcJh5FfA=
github.com/imdario/mergo v0.3.13 h1:lFzP57bqS/wsqKssCGmtLAb8A0wKjLGrve2q3PPVcBk=
github.com/imdario/mergo v0.3.13/go.mod h1:4lJ1jqUDcsbIECGy0RUJAXNIhg+6ocWgb1ALK2O4oXg=
github.com/ipfs/boxo v0.41.0 h1:diKlFosOG2e1mgSO1CXqcMSnHvtn6ubUvaCf9iF8AIY=
github.com/ipfs/boxo v0.41.0/go.mod h1:1Fo36UVVvq3XAZwMDD82Cm4JTUi5x1k3AsJlg9DttOY=
github.com/ipfs/go-block-format v0.2.4 h1:pgsT9i8zB4YQkBIQRrBwqbQiXPogRCiQnfxd2bC4koI=
github.com/ipfs/go-block-format v0.2.4/go.mod h1:YpXrOge8ARskfuJuqjvJTYr4v6o9IZWgK2EEIMAhpcU=
github.com/ipfs/go-cid v0.6.2 h1:VuGwJd+KJTaMJ4S4d5EEf9SXc17YUblS5axCbocn9YE=
github.com/ipfs/go-cid v0.6.2/go.mod h1:Xhwg8NzHeK9xPCEZkCw4idzPiuNMpX3fARuI5Iwj1Lo=
github.com/ipfs/go-datastore v0.9.2 h1:HJOgAmvWPRMHiwD8JHBzGZQNTKhuFGYfp8bNPwye28g=
github.com/ipfs/go-datastore v0.9.2/go.mod h1:VIjDxnINIcCqBMaB8LGggHfYY7PalKWfPtRMFeOU4q4=
github.com/ipfs/go-detect-race v0.0.1 h1:qX/xay2W3E4Q1U7d9lNs1sU9nvguX0a7319XbyQ6cOk=
github.com/ipfs/go-detect-race v0.0.1/go.mod h1:8BNT7shDZPo99Q74BpGMK+4D8Mn4j46UU0LZ723meps=
github.com/ipfs/go-log/v2 v2.9.2 h1:O/5BB0elpkRILvT24rCJ5976wWd7u0nJ436T3rdYdc4=
github.com/ipfs/go-log/v2 v2.9.2/go.mod h1:RziRwwXWhndlk8L75RnEe0zeAYaq2heKtEMc3jqUov0=
github.com/ipfs/go-test v0.4.1 h1:n6uNSakIgpTQIRorqNg2O02aMIFDLQk2z4rBfrlD3Uw=
github.com/ipfs/go-test v0.4.1/go.mod h1:QmvVBf9kClNtRuFow4DASq03eFvjKla4Fy/UAkeeLO8=
github.com/ipld/go-ipld-prime v0.24.0 h1:6th8Z6Peh5bCWuRAVZcDO1sHzZdVF6F2cCCDG3681tg=
github.com/ipld/go-ipld-prime v0.24.0/go.mod h1:DYZxr/5caLNFbcuU6zLOgwSW7CgUEoC4wJiZMEU8Zhs=
github.com/itchyny/base58-go v0.0.5 h1:uv3ieMgCtuE9HtN0Gux375+GOApFnifLkyvSseHBaH0=
github.com/itchyny/base58-go v0.0.5/go.mod h1:SrMWPE3DFuJJp1M/RUhu4fccp/y9AlB8AL3o3duPToU=
github.com/jackpal/go-nat-pmp v1.0.2 h1:KzKSgb7qkJvOUTqYl9/Hg/me3pWgBmERKrTGD7BdWus=
github.com/jackpal/go-nat-pmp v1.0.2/go.mod h1:QPH045xvCAeXUZOxsnwmrtiCoxIr9eob+4orBN1SBKc=
github.com/jbenet/go-temp-err-catcher v0.1.0 h1:zpb3ZH6wIE8Shj2sKS+khgRvf7T7RABoLk/+KKHggpk=
github.com/jbenet/go-temp-err-catcher v0.1.0/go.mod h1:0kJRvmDZXNMIiJirNPEYfhpPwbGVtZVWC34vc5WLsDk=
github.com/jessevdk/go-flags v1.4.0/go.mod h1:4FA24M0QyGHXBuZZK/XkWh8h0e1EYbRYJSGM75WSRxI=
github.com/jtolds/gls v4.20.0+incompatible h1:xdiiI2gbIgH/gLH7ADydsJ1uDOEzR8yvV7C0MuV77Wo=
github.com/jtolds/gls v4.20.0+incompatible/go.mod h1:QJZ7F/aHp+rZTRtaJ1ow/lLfFfVYBRgL+9YlvaHOwJU=
github.com/klauspost/cpuid/v2 v2.4.0 h1:S6Hrbc7+ywsr0r+RLapfGBHfyefhCTwEh3A0tV913Dw=
github.com/klauspost/cpuid/v2 v2.4.0/go.mod h1:19jmZ9mjzoF//ddRSUsv0zfBTJWh3QJh9FNxZTMrGxU=
github.com/koron/go-ssdp v0.9.1 h1:zvxbAAuJftJIZ8Jh8mda+LI7V92hYZf/sKprmOxpxwA=
github.com/koron/go-ssdp v0.9.1/go.mod h1:C43c047jWkDaeg9YuZlSh/QGqOieuWV6dbhWi/jcaLk=
github.com/kr/pretty v0.2.1/go.mod h1:ipq/a2n7PKx3OHsz4KJII5eveXtPO4qwEXGdVfWzfnI=
github.com/kr/pretty v0.3.1 h1:flRD4NNwYAUpkphVc1HcthR4KEIFJ65n8Mw5qdRn3LE=
github.com/kr/pretty v0.3.1/go.mod h1:hoEshYVHaxMs3cyo3Yncou5ZscifuDolrwPKZanG3xk=
github.com/kr/pty v1.1.1/go.mod h1:pFQYn66WHrOpPYNljwOMqo10TkYh1fy3cYio2l3bCsQ=
github.com/kr/text v0.1.0/go.mod h1:4Jbv+DJW3UT/LiOwJeYQe1efqtUx/iVham/4vfdArNI=
github.com/kr/text v0.2.0 h1:5Nx0Ya0ZqY2ygV366QzturHI13Jq95ApcVaJBhpS+AY=
github.com/kr/text v0.2.0/go.mod h1:eLer722TekiGuMkidMxC/pM04lWEeraHUUmBw8l2grE=
github.com/libp2p/go-buffer-pool v0.1.0 h1:oK4mSFcQz7cTQIfqbe4MIj9gLW+mnanjyFtc6cdF0Y8=
github.com/libp2p/go-buffer-pool v0.1.0/go.mod h1:N+vh8gMqimBzdKkSMVuydVDq+UV5QTWy5HSiZacSbPg=
github.com/libp2p/go-cidranger v1.1.0 h1:ewPN8EZ0dd1LSnrtuwd4709PXVcITVeuwbag38yPW7c=
github.com/libp2p/go-cidranger v1.1.0/go.mod h1:KWZTfSr+r9qEo9OkI9/SIEeAtw+NNoU0dXIXt15Okic=
github.com/libp2p/go-flow-metrics v0.3.0 h1:q31zcHUvHnwDO0SHaukewPYgwOBSxtt830uJtUx6784=
github.com/libp2p/go-flow-metrics v0.3.0/go.mod h1:nuhlreIwEguM1IvHAew3ij7A8BMlyHQJ279ao24eZZo=
github.com/libp2p/go-libp2p v0.49.0 h1:ibXuYPIHmMIPShob1BktQvSuFQkq/MemhQOLKfGujjw=
github.com/libp2p/go-libp2p v0.49.0/go.mod h1:lzjVcOBk5fCn1QD2XbSOKLZesB6gEsry8SLjCsAAGT4=
github.com/libp2p/go-libp2p-asn-util v0.4.1 h1:xqL7++IKD9TBFMgnLPZR6/6iYhawHKHl950SO9L6n94=
github.com/libp2p/go-libp2p-asn-util v0.4.1/go.mod h1:d/NI6XZ9qxw67b4e+NgpQexCIiFYJjErASrYW4PFDN8=
github.com/libp2p/go-libp2p-kad-dht v0.42.2 h1:5RtESYeBbjaF+KIPmU47xz2DOb2iLqvoRCZcsjxCS48=
github.com/libp2p/go-libp2p-kad-dht v0.42.2/go.mod h1:oLGZ7xq317zXmoeJe0dwgUdOeWeJ85MDJ/+fbKqFoK0=
github.com/libp2p/go-libp2p-kbucket v0.9.0 h1:9kTf74R8CHGIk3QK+gwEOnJ/t+JzuxqQSfAAASl1VhM=
github.com/libp2p/go-libp2p-kbucket v0.9.0/go.mod h1:lKhHVjRq1z/Cl/bFzB2vPzYY0KCdmON6HlBwEAanqjk=
github.com/libp2p/go-libp2p-record v0.3.1 h1:cly48Xi5GjNw5Wq+7gmjfBiG9HCzQVkiZOUZ8kUl+Fg=
github.com/libp2p/go-libp2p-record v0.3.1/go.mod h1:T8itUkLcWQLCYMqtX7Th6r7SexyUJpIyPgks757td/E=
github.com/libp2p/go-libp2p-routing-helpers v0.7.5 h1:HdwZj9NKovMx0vqq6YNPTh6aaNzey5zHD7HeLJtq6fI=
github.com/libp2p/go-libp2p-routing-helpers v0.7.5/go.mod h1:3YaxrwP0OBPDD7my3D0KxfR89FlcX/IEbxDEDfAmj98=
github.com/libp2p/go-libp2p-testing v0.12.0 h1:EPvBb4kKMWO29qP4mZGyhVzUyR25dvfUIK5WDu6iPUA=
github.com/libp2p/go-libp2p-testing v0.12.0/go.mod h1:KcGDRXyN7sQCllucn1cOOS+Dmm7ujhfEyXQL5lvkcPg=
github.com/libp2p/go-msgio v0.3.0 h1:mf3Z8B1xcFN314sWX+2vOTShIE0Mmn2TXn3YCUQGNj0=
github.com/libp2p/go-msgio v0.3.0/go.mod h1:nyRM819GmVaF9LX3l03RMh10QdOroF++NBbxAb0mmDM=
github.com/libp2p/go-netroute v0.4.0 h1:sZZx9hyANYUx9PZyqcgE/E1GUG3iEtTZHUEvdtXT7/Q=
github.com/libp2p/go-netroute v0.4.0/go.mod h1:Nkd5ShYgSMS5MUKy/MU2T57xFoOKvvLR92Lic48LEyA=
github.com/libp2p/go-reuseport v0.4.0 h1:nR5KU7hD0WxXCJbmw7r2rhRYruNRl2koHw8fQscQm2s=
github.com/libp2p/go-reuseport v0.4.0/go.mod h1:ZtI03j/wO5hZVDFo2jKywN6bYKWLOy8Se6DrI2E1cLU=
github.com/libp2p/go-yamux/v5 v5.1.0 h1:8Qlxj4E9JGJAQVW6+uj2o7mqkqsIVlSUGmTWhlXzoHE=
github.com/libp2p/go-yamux/v5 v5.1.0/go.mod h1:tgIQ07ObtRR/I0IWsFOyQIL9/dR5UXgc2s8xKmNZv1o=
github.com/libp2p/zeroconf/v2 v2.2.0 h1:Cup06Jv6u81HLhIj1KasuNM/RHHrJ8T7wOTS4+Tv53Q=
github.com/libp2p/zeroconf/v2 v2.2.0/go.mod h1:fuJqLnUwZTshS3U/bMRJ3+ow/v9oid1n0DmyYyNO1Xs=
github.com/lxn/walk v0.0.0-20210112085537-c389da54e794 h1:NVRJ0Uy0SOFcXSKLsS65OmI1sgCCfiDUPj+cwnH7GZw=
github.com/lxn/walk v0.0.0-20210112085537-c389da54e794/go.mod h1:E23UucZGqpuUANJooIbHWCufXvOcT6E7Stq81gU+CSQ=
github.com/lxn/win v0.0.0-20210218163916-a377121e959e h1:H+t6A/QJMbhCSEH5rAuRxh+CtW96g0Or0Fxa9IKr4uc=
github.com/lxn/win v0.0.0-20210218163916-a377121e959e/go.mod h1:KxxjdtRkfNoYDCUP5ryK7XJJNTnpC8atvtmTheChOtk=
github.com/marcopolo/simnet v0.0.7 h1:DpH8BMGsF9+1w13L8rvCaAhb6nYJdY+dIXncDrssvUs=
github.com/marcopolo/simnet v0.0.7/go.mod h1:tfQF1u2DmaB6WHODMtQaLtClEf3a296CKQLq5gAsIS0=
github.com/marten-seemann/tcp v0.0.0-20210406111302-dfbc87cc63fd h1:br0buuQ854V8u83wA0rVZ8ttrq5CpaPZdvrK0LP2lOk=
github.com/marten-seemann/tcp v0.0.0-20210406111302-dfbc87cc63fd/go.mod h1:QuCEs1Nt24+FYQEqAAncTDPJIuGs+LxK1MCiFL25pMU=
github.com/mattn/go-isatty v0.0.22 h1:j8l17JJ9i6VGPUFUYoTUKPSgKe/83EYU2zBC7YNKMw4=
github.com/mattn/go-isatty v0.0.22/go.mod h1:ZXfXG4SQHsB/w3ZeOYbR0PrPwLy+n6xiMrJlRFqopa4=
github.com/miekg/dns v1.1.43/go.mod h1:+evo5L0630/F6ca/Z9+GAqzhjGyn8/c+TBaOyfEl0V4=
github.com/miekg/dns v1.1.72 h1:vhmr+TF2A3tuoGNkLDFK9zi36F2LS+hKTRW0Uf8kbzI=
github.com/miekg/dns v1.1.72/go.mod h1:+EuEPhdHOsfk6Wk5TT2CzssZdqkmFhf8r+aVyDEToIs=
github.com/mikioh/tcp v0.0.0-20190314235350-803a9b46060c h1:bzE/A84HN25pxAuk9Eej1Kz9OUelF97nAc82bDquQI8=
github.com/mikioh/tcp v0.0.0-20190314235350-803a9b46060c/go.mod h1:0SQS9kMwD2VsyFEB++InYyBJroV/FRmBgcydeSUcJms=
github.com/mikioh/tcpinfo v0.0.0-20190314235526-30a79bb1804b h1:z78hV3sbSMAUoyUMM0I83AUIT6Hu17AWfgjzIbtrYFc=
github.com/mikioh/tcpinfo v0.0.0-20190314235526-30a79bb1804b/go.mod h1:lxPUiZwKoFL8DUUmalo2yJJUCxbPKtm8OKfqr2/FTNU=
github.com/mikioh/tcpopt v0.0.0-20190314235656-172688c1accc h1:PTfri+PuQmWDqERdnNMiD9ZejrlswWrCpBEZgWOiTrc=
github.com/mikioh/tcpopt v0.0.0-20190314235656-172688c1accc/go.mod h1:cGKTAVKx4SxOuR/czcZ/E2RSJ3sfHs8FpHhQ5CWMf9s=
github.com/minio/blake2b-simd v0.0.0-20160723061019-3f5f724cb5b1/go.mod h1:pD8RvIylQ358TN4wwqatJ8rNavkEINozVn9DtGI3dfQ=
github.com/minio/sha256-simd v0.1.1-0.20190913151208-6de447530771/go.mod h1:B5e1o+1/KgNmWrSQK08Y6Z1Vb5pwIktudl0J58iy0KM=
github.com/minio/sha256-simd v1.0.1 h1:6kaan5IFmwTNynnKKpDHe6FWHohJOHhCPchzK49dzMM=
github.com/minio/sha256-simd v1.0.1/go.mod h1:Pz6AKMiUdngCLpeTL/RJY1M9rUuPMYujV5xJjtbRSN8=
github.com/mr-tron/base58 v1.1.2/go.mod h1:BinMc/sQntlIE1frQmRFPUoPA1Zkr8VRgBdjWI2mNwc=
github.com/mr-tron/base58 v1.3.0 h1:K6Y13R2h+dku0wOqKtecgRnBUBPrZzLZy5aIj8lCcJI=
github.com/mr-tron/base58 v1.3.0/go.mod h1:2BuubE67DCSWwVfx37JWNG8emOC0sHEU4/HpcYgCLX8=
github.com/multiformats/go-base32 v0.1.0 h1:pVx9xoSPqEIQG8o+UbAe7DNi51oej1NtK+aGkbLYxPE=
github.com/multiformats/go-base32 v0.1.0/go.mod h1:Kj3tFY6zNr+ABYMqeUNeGvkIC/UYgtWibDcT0rExnbI=
github.com/multiformats/go-base36 v0.2.0 h1:lFsAbNOGeKtuKozrtBsAkSVhv1p9D0/qedU9rQyccr0=
github.com/multiformats/go-base36 v0.2.0/go.mod h1:qvnKE++v+2MWCfePClUEjE78Z7P2a1UV0xHgWc0hkp4=
github.com/multiformats/go-multiaddr v0.1.1/go.mod h1:aMKBKNEYmzmDmxfX88/vz+J5IU55txyt0p4aiWVohjo=
github.com/multiformats/go-multiaddr v0.16.1 h1:fgJ0Pitow+wWXzN9do+1b8Pyjmo8m5WhGfzpL82MpCw=
github.com/multiformats/go-multiaddr v0.16.1/go.mod h1:JSVUmXDjsVFiW7RjIFMP7+Ev+h1DTbiJgVeTV/tcmP0=
github.com/multiformats/go-multiaddr-dns v0.6.0 h1:yKIW08WJHSPJ8bDAT2O/5fypCaUu9Bjl8r/1eJ4XAW8=
github.com/multiformats/go-multiaddr-dns v0.6.0/go.mod h1:dwIQwdORZfnNQCeS7xLXyn+7626oRmMsVP30Uronhf0=
github.com/multiformats/go-multiaddr-fmt v0.1.0 h1:WLEFClPycPkp4fnIzoFoV9FVd49/eQsuaL3/CWe167E=
github.com/multiformats/go-multiaddr-fmt v0.1.0/go.mod h1:hGtDIW4PU4BqJ50gW2quDuPVjyWNZxToGUh/HwTZYJo=
github.com/multiformats/go-multibase v0.3.0 h1:8helZD2+4Db7NNWFiktk2NePbF0boolBe6bDQvM4r68=
github.com/multiformats/go-multibase v0.3.0/go.mod h1:MoBLQPCkRTOL3eveIPO81860j2AQY8JwcnNlRkGRUfI=
github.com/multiformats/go-multicodec v0.10.0 h1:UpP223cig/Cx8J76jWt91njpK3GTAO1w02sdcjZDSuc=
github.com/multiformats/go-multicodec v0.10.0/go.mod h1:wg88pM+s2kZJEQfRCKBNU+g32F5aWBEjyFHXvZLTcLI=
github.com/multiformats/go-multihash v0.0.8/go.mod h1:YSLudS+Pi8NHE7o6tb3D8vrpKa63epEDmG8nTduyAew=
github.com/multiformats/go-multihash v0.2.3 h1:7Lyc8XfX/IY2jWb/gI7JP+o7JEq9hOa7BFvVU9RSh+U=
github.com/multiformats/go-multihash v0.2.3/go.mod h1:dXgKXCXjBzdscBLk9JkjINiEsCKRVch90MdaGiKsvSM=
github.com/multiformats/go-multistream v0.6.1 h1:4aoX5v6T+yWmc2raBHsTvzmFhOI8WVOer28DeBBEYdQ=
github.com/multiformats/go-multistream v0.6.1/go.mod h1:ksQf6kqHAb6zIsyw7Zm+gAuVo57Qbq84E27YlYqavqw=
github.com/multiformats/go-varint v0.1.0 h1:i2wqFp4sdl3IcIxfAonHQV9qU5OsZ4Ts9IOoETFs5dI=
github.com/multiformats/go-varint v0.1.0/go.mod h1:5KVAVXegtfmNQQm/lCY+ATvDzvJJhSkUlGQV9wgObdI=
github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 h1:C3w9PqII01/Oq1c1nUAm88MOHcQC9l5mIlSMApZMrHA=
github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822/go.mod h1:+n7T8mK8HuQTcFwEeznm/DIxMOiR9yIdICNftLE1DvQ=
github.com/nknorg/mockconn-go v0.0.0-20230125231524-d664e728352a/go.mod h1:/SvBORYxt9wlm8ZbaEFEri6ooOSDcU3ovU0L2eRRdS4=
github.com/nknorg/ncp-go v1.0.5 h1:alJjq6bi6tRwUAAv932FIfE/R3S7DRR0pgXOgBXNHAk=
github.com/nknorg/ncp-go v1.0.5/go.mod h1:ze88qf5e9/DBXSOaJPL2Caa0IbdZJLzESAFM1S7mGwg=
github.com/nknorg/nkn-sdk-go v1.4.8 h1:FDrciYYJNQ4gKkAVw/N6cL4JcLVYDzi1UofjXFJL3fw=
github.com/nknorg/nkn-sdk-go v1.4.8/go.mod h1:0R0uX32pMM/iqvKOdRDXzEGLOpBj1oNZDzuM8/YpGIM=
github.com/nknorg/nkn/v2 v2.2.1-0.20240509224846-24ade56074a3 h1:HES8PokvbjW7xjcJK094C5nLfTe01WZpi48zLasM09o=
github.com/nknorg/nkn/v2 v2.2.1-0.20240509224846-24ade56074a3/go.mod h1:S0TtUvuE+hnihwOInhxNkS/c8ybTZUttsF4Vi9RYBwI=
github.com/nknorg/nkngomobile v0.0.0-20220615081414-671ad1afdfa9 h1:Gr37j7Ttvcn8g7TdC5fs6Y6IJKdmfqCvj03UbsrS77o=
github.com/nknorg/nkngomobile v0.0.0-20220615081414-671ad1afdfa9/go.mod h1:zNY9NCyBcJCCDrXhwOjKarkW5cngPs/Z82xVNy/wvEA=
github.com/patrickmn/go-cache v2.1.0+incompatible h1:HRMgzkcYKYpi3C8ajMPV8OFXaaRUnok+kx1WdO15EQc=
github.com/patrickmn/go-cache v2.1.0+incompatible/go.mod h1:3Qf8kWWT7OJRJbdiICTKqZju1ZixQ/KpMGzzAfe6+WQ=
github.com/pbnjay/memory v0.0.0-20210728143218-7b4eea64cf58 h1:onHthvaw9LFnH4t2DcNVpwGmV9E1BkGknEliJkfwQj0=
github.com/pbnjay/memory v0.0.0-20210728143218-7b4eea64cf58/go.mod h1:DXv8WO4yhMYhSNPKjeNKa5WY9YCIEBRbNzFFPJbWO6Y=
github.com/pborman/uuid v1.2.0 h1:J7Q5mO4ysT1dv8hyrUGHb9+ooztCXu1D8MY8DZYsu3g=
github.com/pborman/uuid v1.2.0/go.mod h1:X/NO0urCmaxf9VXbdlT7C2Yzkj2IKimNn4k+gtPdI/k=
github.com/pion/datachannel v1.5.10 h1:ly0Q26K1i6ZkGf42W7D4hQYR90pZwzFOjTq5AuCKk4o=
github.com/pion/datachannel v1.5.10/go.mod h1:p/jJfC9arb29W7WrxyKbepTU20CFgyx5oLo8Rs4Py/M=
github.com/pion/dtls/v3 v3.1.4 h1:QhvtMflMfu9Kf0RcDC5BJBle4caPskByrKQR6uuYqpY=
github.com/pion/dtls/v3 v3.1.4/go.mod h1:cr/qotLISUw/9C1m83ZPNZtj9WnXkYLpfCptPqbkInc=
github.com/pion/ice/v4 v4.0.10 h1:P59w1iauC/wPk9PdY8Vjl4fOFL5B+USq1+xbDcN6gT4=
github.com/pion/ice/v4 v4.0.10/go.mod h1:y3M18aPhIxLlcO/4dn9X8LzLLSma84cx6emMSu14FGw=
github.com/pion/interceptor v0.1.40 h1:e0BjnPcGpr2CFQgKhrQisBU7V3GXK6wrfYrGYaU6Jq4=
github.com/pion/interceptor v0.1.40/go.mod h1:Z6kqH7M/FYirg3frjGJ21VLSRJGBXB/KqaTIrdqnOic=
github.com/pion/logging v0.2.4 h1:tTew+7cmQ+Mc1pTBLKH2puKsOvhm32dROumOZ655zB8=
github.com/pion/logging v0.2.4/go.mod h1:DffhXTKYdNZU+KtJ5pyQDjvOAh/GsNSyv1lbkFbe3so=
github.com/pion/mdns/v2 v2.0.7 h1:c9kM8ewCgjslaAmicYMFQIde2H9/lrZpjBkN8VwoVtM=
github.com/pion/mdns/v2 v2.0.7/go.mod h1:vAdSYNAT0Jy3Ru0zl2YiW3Rm/fJCwIeM0nToenfOJKA=
github.com/pion/randutil v0.1.0 h1:CFG1UdESneORglEsnimhUjf33Rwjubwj6xfiOXBa3mA=
github.com/pion/randutil v0.1.0/go.mod h1:XcJrSMMbbMRhASFVOlj/5hQial/Y8oH/HVo7TBZq+j8=
github.com/pion/rtcp v1.2.16 h1:fk1B1dNW4hsI78XUCljZJlC4kZOPk67mNRuQ0fcEkSo=
github.com/pion/rtcp v1.2.16/go.mod h1:/as7VKfYbs5NIb4h6muQ35kQF/J0ZVNz2Z3xKoCBYOo=
github.com/pion/rtp v1.8.19 h1:jhdO/3XhL/aKm/wARFVmvTfq0lC/CvN1xwYKmduly3c=
github.com/pion/rtp v1.8.19/go.mod h1:bAu2UFKScgzyFqvUKmbvzSdPr+NGbZtv6UB2hesqXBk=
github.com/pion/sctp v1.8.39 h1:PJma40vRHa3UTO3C4MyeJDQ+KIobVYRZQZ0Nt7SjQnE=
github.com/pion/sctp v1.8.39/go.mod h1:cNiLdchXra8fHQwmIoqw0MbLLMs+f7uQ+dGMG2gWebE=
github.com/pion/sdp/v3 v3.0.18 h1:l0bAXazKHpepazVdp+tPYnrsy9dfh7ZbT8DxesH5ZnI=
github.com/pion/sdp/v3 v3.0.18/go.mod h1:ZREGo6A9ZygQ9XkqAj5xYCQtQpif0i6Pa81HOiAdqQ8=
github.com/pion/srtp/v3 v3.0.6 h1:E2gyj1f5X10sB/qILUGIkL4C2CqK269Xq167PbGCc/4=
github.com/pion/srtp/v3 v3.0.6/go.mod h1:BxvziG3v/armJHAaJ87euvkhHqWe9I7iiOy50K2QkhY=
github.com/pion/stun/v3 v3.1.5 h1:Y1FHlhaI6+4UoC5i/zQf4F7JvdZtB24/05oyy/GF1x8=
github.com/pion/stun/v3 v3.1.5/go.mod h1:zRUghXSQU32Lx5orJsz3uYMkIihweXb3mu5gIns02fs=
github.com/pion/transport/v3 v3.0.7 h1:iRbMH05BzSNwhILHoBoAPxoB9xQgOaJk+591KC9P1o0=
github.com/pion/transport/v3 v3.0.7/go.mod h1:YleKiTZ4vqNxVwh77Z0zytYi7rXHl7j6uPLGhhz9rwo=
github.com/pion/transport/v4 v4.0.2 h1:ifYlPqNwsy6aKQ9y8yzxXlHae5431ZrH2avkD/Rn6Tk=
github.com/pion/transport/v4 v4.0.2/go.mod h1:06hFI+jCFcok2X2MekVufNZ/uzNZXivGBPfviSVcjgM=
github.com/pion/turn/v4 v4.0.2 h1:ZqgQ3+MjP32ug30xAbD6Mn+/K4Sxi3SdNOTFf+7mpps=
github.com/pion/turn/v4 v4.0.2/go.mod h1:pMMKP/ieNAG/fN5cZiN4SDuyKsXtNTr0ccN7IToA1zs=
github.com/pion/webrtc/v4 v4.1.2 h1:mpuUo/EJ1zMNKGE79fAdYNFZBX790KE7kQQpLMjjR54=
github.com/pion/webrtc/v4 v4.1.2/go.mod h1:xsCXiNAmMEjIdFxAYU0MbB3RwRieJsegSB2JZsGN+8U=
github.com/pmezard/go-difflib v1.0.0 h1:4DBwDE0NGyQoBHbLQYPwSUPoCMWR5BEzIk/f1lZbAQM=
github.com/pmezard/go-difflib v1.0.0/go.mod h1:iKH77koFhYxTK1pcRnkKkqfTogsbg7gZNVY4sRDYZ/4=
github.com/polydawn/refmt v0.90.0 h1:58BfEsP+G4uIRD9ApJTFsag+Mw+QQlZuH9uI/lPmjfY=
github.com/polydawn/refmt v0.90.0/go.mod h1:XAlDMOunevTYDsZtOKQd8itHXFMsX/QtDkPHaj6ZLxk=
github.com/prometheus/client_golang v1.24.1 h1:JnJkREXzWxUdCuPFpIWZiPispT9xVV59uiuyR2bPlnU=
github.com/prometheus/client_golang v1.24.1/go.mod h1:F+oSRECHg4sse5ucfYpYDeIv/hu68Zo0uoHKetWnzcE=
github.com/prometheus/client_model v0.6.2 h1:oBsgwpGs7iVziMvrGhE53c/GrLUsZdHnqNwqPLxwZyk=
github.com/prometheus/client_model v0.6.2/go.mod h1:y3m2F6Gdpfy6Ut/GBsUqTWZqCUvMVzSfMLjcu6wAwpE=
github.com/prometheus/common v0.70.1 h1:1HvjP4D5oL3t8RsPlwxA9onvvStjtIHYE5XuuwOi/PY=
github.com/prometheus/common v0.70.1/go.mod h1:VdFUQDMZK3VLkurFUVhia6uys/0suUp86TJz5qbJRhc=
github.com/prometheus/procfs v0.21.1 h1:GljZCt+zSTS+NZq88cyQ1LjZ+RCHp3uVuabBWA5+OJI=
github.com/prometheus/procfs v0.21.1/go.mod h1:aB55Cww9pdSJVHk0hUf0inxWyyjPogFIjmHKYgMKmtY=
github.com/quic-go/go-ossfuzz-seeds v0.1.0 h1:APacT+iIaNF6fd8AGEiN3bT/Jtkd2jz4v4TzM7MFjy0=
github.com/quic-go/go-ossfuzz-seeds v0.1.0/go.mod h1:3IOHRbJIc+L6YKMwfDtJAM9Vj9k0YY4muhuyUYk5tbk=
github.com/quic-go/qpack v0.6.0 h1:g7W+BMYynC1LbYLSqRt8PBg5Tgwxn214ZZR34VIOjz8=
github.com/quic-go/qpack v0.6.0/go.mod h1:lUpLKChi8njB4ty2bFLX2x4gzDqXwUpaO1DP9qMDZII=
github.com/quic-go/quic-go v0.60.0 h1:xcQioE8OM66UQLeUMHltK1CCcOu3JbVB4JAQdDQSB+0=
github.com/quic-go/quic-go v0.60.0/go.mod h1:wpKpjmPpftl30sL6pFh7REVpjbcCVy4zt2vDyK1TuJk=
github.com/quic-go/webtransport-go v0.11.1 h1:rrFQMO+7/52ZDJ04fsrjIaWqn6q1z1MYo9iVFq6JtbA=
github.com/quic-go/webtransport-go v0.11.1/go.mod h1:SHgEzUFVyj+9WUSuGB1P6Zd351Pww2leWV3SwlTovkA=
github.com/rogpeppe/go-internal v1.14.1 h1:UQB4HGPB6osV0SQTLymcB4TgvyWu6ZyliaW0tI/otEQ=
github.com/rogpeppe/go-internal v1.14.1/go.mod h1:MaRKkUm5W0goXpeCfT7UZI6fk/L7L7so1lCWt35ZSgc=
github.com/skip2/go-qrcode v0.0.0-20200617195104-da1b6568686e h1:MRM5ITcdelLK2j1vwZ3Je0FKVCfqOLp5zO6trqMLYs0=
github.com/skip2/go-qrcode v0.0.0-20200617195104-da1b6568686e/go.mod h1:XV66xRDqSt+GTGFMVlhk3ULuV0y9ZmzeVGR4mloJI3M=
github.com/smarty/assertions v1.15.0 h1:cR//PqUBUiQRakZWqBiFFQ9wb8emQGDb0HeGdqGByCY=
github.com/smarty/assertions v1.15.0/go.mod h1:yABtdzeQs6l1brC900WlRNwj6ZR55d7B+E8C6HtKdec=
github.com/smartystreets/goconvey v1.8.1 h1:qGjIddxOk4grTu9JPOU31tVfq3cNdBlNa5sSznIX1xY=
github.com/smartystreets/goconvey v1.8.1/go.mod h1:+/u4qLyY6x1jReYOp7GOM2FSt8aP9CzCZL03bI28W60=
github.com/spaolacci/murmur3 v1.1.0 h1:7c1g84S4BPRrfL5Xrdp6fOJ206sU9y293DDHaoy0bLI=
github.com/spaolacci/murmur3 v1.1.0/go.mod h1:JwIasOWyU6f++ZhiEuf87xNszmSA2myDM2Kzu9HwQUA=
github.com/stretchr/objx v0.1.0/go.mod h1:HFkY916IF+rwdDfMAkV7OtwuqBVzrE8GR6GFx+wExME=
github.com/stretchr/objx v0.4.0/go.mod h1:YvHI0jy2hoMjB+UWwv71VJQ9isScKT/TqJzVSSt89Yw=
github.com/stretchr/objx v0.5.0/go.mod h1:Yh+to48EsGEfYuaHDzXPcE3xhTkx73EhmCGUpEOglKo=
github.com/stretchr/testify v1.3.0/go.mod h1:M5WIy9Dh21IEIfnGCwXGc5bZfKNJtfHm1UVUgZn+9EI=
github.com/stretchr/testify v1.4.0/go.mod h1:j7eGeouHqKxXV5pUuKE4zz7dFj8WfuZ+81PSLYec5m4=
github.com/stretchr/testify v1.7.1/go.mod h1:6Fq8oRcR53rry900zMqJjRRixrwX3KX962/h/Wwjteg=
github.com/stretchr/testify v1.8.0/go.mod h1:yNjHg4UonilssWZ8iaSj1OCr/vHnekPRkoO+kdMU+MU=
github.com/stretchr/testify v1.8.1/go.mod h1:w2LPCIKwWwSfY2zedu0+kehJoqGctiVI29o6fzry7u4=
github.com/stretchr/testify v1.11.1 h1:7s2iGBzp5EwR7/aIZr8ao5+dra3wiQyKjjFuvgVKu7U=
github.com/stretchr/testify v1.11.1/go.mod h1:wZwfW3scLgRK+23gO65QZefKpKQRnfz6sD981Nm4B6U=
github.com/whyrusleeping/go-keyspace v0.0.0-20160322163242-5b898ac5add1 h1:EKhdznlJHPMoKr0XTrX+IlJs1LH3lyx2nfr1dOlZ79k=
github.com/whyrusleeping/go-keyspace v0.0.0-20160322163242-5b898ac5add1/go.mod h1:8UvriyWtv5Q5EOgjHaSseUEdkQfvwFv1I/In/O2M9gc=
github.com/wlynxg/anet v0.0.5 h1:J3VJGi1gvo0JwZ/P1/Yc/8p63SoW98B5dHkYDmpgvvU=
github.com/wlynxg/anet v0.0.5/go.mod h1:eay5PRQr7fIVAMbTbchTnO9gG65Hg/uYGdc7mguHxoA=
go.opentelemetry.io/auto/sdk v1.2.1 h1:jXsnJ4Lmnqd11kwkBV2LgLoFMZKizbCi5fNZ/ipaZ64=
go.opentelemetry.io/auto/sdk v1.2.1/go.mod h1:KRTj+aOaElaLi+wW1kO/DZRXwkF4C5xPbEe3ZiIhN7Y=
go.opentelemetry.io/otel v1.44.0 h1:JjwHmHpA4iZ3wBxluu2fbbE7j4kqlE8jXyAyPXH7HqU=
go.opentelemetry.io/otel v1.44.0/go.mod h1:BMgjTHL9WPRlRjL2oZCBTL4whCGtXch2H4BhOPIAyYc=
go.opentelemetry.io/otel/metric v1.44.0 h1:1w0gILTcHdr3YI+ixLyjemwrVnsMURbTZFrSYCdDdmc=
go.opentelemetry.io/otel/metric v1.44.0/go.mod h1:8O7hanEPBNgEMmybD3s2VBKcgWOCsA6tzHBPODAiquo=
go.opentelemetry.io/otel/trace v1.44.0 h1:jxF5CsGYCe74MCRx2X4g7WsY/VBKRqqpNvXlX/6gtIk=
go.opentelemetry.io/otel/trace v1.44.0/go.mod h1:oLl1jrMQAVo6v3GAggN+1VH9VIz9iUSvW53sW1Q8PIE=
go.uber.org/dig v1.19.0 h1:BACLhebsYdpQ7IROQ1AGPjrXcP5dF80U3gKoFzbaq/4=
go.uber.org/dig v1.19.0/go.mod h1:Us0rSJiThwCv2GteUN0Q7OKvU7n5J4dxZ9JKUXozFdE=
go.uber.org/fx v1.24.0 h1:wE8mruvpg2kiiL1Vqd0CC+tr0/24XIB10Iwp2lLWzkg=
go.uber.org/fx v1.24.0/go.mod h1:AmDeGyS+ZARGKM4tlH4FY2Jr63VjbEDJHtqXTGP5hbo=
go.uber.org/goleak v1.3.0 h1:2K3zAYmnTNqV73imy9J1T3WC+gmCePx2hEGkimedGto=
go.uber.org/goleak v1.3.0/go.mod h1:CoHD4mav9JJNrW/WLlf7HGZPjdw8EucARQHekz1X6bE=
go.uber.org/mock v0.6.0 h1:hyF9dfmbgIX5EfOdasqLsWD6xqpNZlXblLB/Dbnwv3Y=
go.uber.org/mock v0.6.0/go.mod h1:KiVJ4BqZJaMj4svdfmHM0AUx4NJYO8ZNpPnZn1Z+BBU=
go.uber.org/multierr v1.11.0 h1:blXXJkSxSSfBVBlC76pxqeO+LN3aDfLQo+309xJstO0=
go.uber.org/multierr v1.11.0/go.mod h1:20+QtiLqy0Nd6FdQB9TLXag12DsQkrbs3htMFfDN80Y=
go.uber.org/zap v1.28.0 h1:IZzaP1Fv73/T/pBMLk4VutPl36uNC+OSUh3JLG3FIjo=
go.uber.org/zap v1.28.0/go.mod h1:rDLpOi171uODNm/mxFcuYWxDsqWSAVkFdX4XojSKg/Q=
go.yaml.in/yaml/v2 v2.4.4 h1:tuyd0P+2Ont/d6e2rl3be67goVK4R6deVxCUX5vyPaQ=
go.yaml.in/yaml/v2 v2.4.4/go.mod h1:gMZqIpDtDqOfM0uNfy0SkpRhvUryYH0Z6wdMYcacYXQ=
go.yaml.in/yaml/v3 v3.0.4 h1:tfq32ie2Jv2UxXFdLJdh3jXuOzWiL1fo0bu/FbuKpbc=
go.yaml.in/yaml/v3 v3.0.4/go.mod h1:DhzuOOF2ATzADvBadXxruRBLzYTpT36CKvDb3+aBEFg=
golang.org/x/crypto v0.0.0-20190308221718-c2843e01d9a2/go.mod h1:djNgcEr1/C05ACkg1iLfiJU5Ep61QUkGW8qpdssI0+w=
golang.org/x/crypto v0.0.0-20190611184440-5c40567a22f8/go.mod h1:yigFU9vqHzYiE8UmvKecakEJjdnWj3jj499lnFckfCI=
golang.org/x/crypto v0.0.0-20191011191535-87dc89f01550/go.mod h1:yigFU9vqHzYiE8UmvKecakEJjdnWj3jj499lnFckfCI=
golang.org/x/crypto v0.0.0-20200602180216-279210d13fed/go.mod h1:LzIPMQfyMNhhGPhUkYOs5KpL4U8rLKemX1yGLhDgUto=
golang.org/x/crypto v0.0.0-20210322153248-0c34fe9e7dc2/go.mod h1:T9bdIzuCu7OtxOm1hfPfRQxPLYneinmdGuTeoZ9dtd4=
golang.org/x/crypto v0.54.0 h1:YLIA59K4fiNzHzjnZt2tUJQjQtUWfWbeHBqKtk3eScw=
golang.org/x/crypto v0.54.0/go.mod h1:KWL8ny2AZdGR2cWmzeHrp2azQPGogOv+HeQaVEXC2dk=
golang.org/x/exp v0.0.0-20260718201538-764159d718ef h1:LkZ48HFgy/TvhTI0bcWkjgFkgLyKUwcTbDjS0DUjw+A=
golang.org/x/exp v0.0.0-20260718201538-764159d718ef/go.mod h1:EdfpwwqSu+0Li0mzskwHU6FWDV3t9Q+RZDo3QMUtL3Q=
golang.org/x/lint v0.0.0-20200302205851-738671d3881b/go.mod h1:3xt1FjdF8hUf6vQPIChWIBhFzV8gjjsPE/fR3IyQdNY=
golang.org/x/mobile v0.0.0-20230301163155-e0f57694e12c h1:Gk61ECugwEHL6IiyyNLXNzmu8XslmRP2dS0xjIYhbb4=
golang.org/x/mobile v0.0.0-20230301163155-e0f57694e12c/go.mod h1:aAjjkJNdrh3PMckS4B10TGS2nag27cbKR1y2BpUxsiY=
golang.org/x/mod v0.1.1-0.20191105210325-c90efee705ee/go.mod h1:QqPTAvyqsEbceGzBzNggFXnrqF1CaUcvgkdR5Ot7KZg=
golang.org/x/mod v0.38.0 h1:MECBjubtXD7yj4HrhIUcywNaGeNVUdfVnxmPajOk4yk=
golang.org/x/mod v0.38.0/go.mod h1:V6Xz0pq8TQ3dGqVQ1FVHuelZpAL0uNhSkk9ogYP3c40=
golang.org/x/net v0.0.0-20190404232315-eb5bcb51f2a3/go.mod h1:t9HGtf8HONx5eT2rtn7q6eTqICYqUVnKs3thJo3Qplg=
golang.org/x/net v0.0.0-20190620200207-3b0461eec859/go.mod h1:z5CRVTTTmAJ677TzLLGU+0bjPO0LkuOLi4/5GtJWs/s=
golang.org/x/net v0.0.0-20210119194325-5f4716e94777/go.mod h1:m0MpNAwzfU5UDzcl9v0D8zg8gWTRqZa9RBIspLL5mdg=
golang.org/x/net v0.0.0-20210226172049-e18ecbb05110/go.mod h1:m0MpNAwzfU5UDzcl9v0D8zg8gWTRqZa9RBIspLL5mdg=
golang.org/x/net v0.0.0-20210423184538-5f58ad60dda6/go.mod h1:OJAsFXCWl8Ukc7SiCT/9KSuxbyM7479/AVlXFRxuMCk=
golang.org/x/net v0.57.0 h1:K5+3DljvIuDG9/Jv9rvyMywYNFCQ9RSUY6OOTTkT+tE=
golang.org/x/net v0.57.0/go.mod h1:KpXc8iv+r3XplLAG/f7Jsf9RPszJzdR0f58q9vGOuEU=
golang.org/x/sync v0.0.0-20190423024810-112230192c58/go.mod h1:RxMgew5VJxzue5/jJTE5uejpjVlOe/izrB70Jof72aM=
golang.org/x/sync v0.0.0-20210220032951-036812b2e83c/go.mod h1:RxMgew5VJxzue5/jJTE5uejpjVlOe/izrB70Jof72aM=
golang.org/x/sync v0.22.0 h1:SZjpbeLmrCk4xhRSZFNZW5gFUeCeFgjekvI/+gfScek=
golang.org/x/sync v0.22.0/go.mod h1:9xrNwdLfx4jkKbNva9FpL6vEN7evnE43NNNJQ2LF3+0=
golang.org/x/sys v0.0.0-20190215142949-d0b11bdaac8a/go.mod h1:STP8DvDyc/dI5b8T5hshtkjS+E42TnysNCUPdjciGhY=
golang.org/x/sys v0.0.0-20190412213103-97732733099d/go.mod h1:h1NjWce9XRLGQEsW7wpKNCjG9DtNlClVuFLEZdDNbEs=
golang.org/x/sys v0.0.0-20200602225109-6fdc65e7d980/go.mod h1:h1NjWce9XRLGQEsW7wpKNCjG9DtNlClVuFLEZdDNbEs=
golang.org/x/sys v0.0.0-20201018230417-eeed37f84f13/go.mod h1:h1NjWce9XRLGQEsW7wpKNCjG9DtNlClVuFLEZdDNbEs=
golang.org/x/sys v0.0.0-20201119102817-f84b799fce68/go.mod h1:h1NjWce9XRLGQEsW7wpKNCjG9DtNlClVuFLEZdDNbEs=
golang.org/x/sys v0.0.0-20210303074136-134d130e1a04/go.mod h1:h1NjWce9XRLGQEsW7wpKNCjG9DtNlClVuFLEZdDNbEs=
golang.org/x/sys v0.0.0-20210423082822-04245dca01da/go.mod h1:h1NjWce9XRLGQEsW7wpKNCjG9DtNlClVuFLEZdDNbEs=
golang.org/x/sys v0.0.0-20210426080607-c94f62235c83/go.mod h1:h1NjWce9XRLGQEsW7wpKNCjG9DtNlClVuFLEZdDNbEs=
golang.org/x/sys v0.47.0 h1:o7XGOvZQCADBQQ4Y7VNq2dRWQR7JmOUW8Kxx4ZsNgWs=
golang.org/x/sys v0.47.0/go.mod h1:4GL1E5IUh+htKOUEOaiffhrAeqysfVGipDYzABqnCmw=
golang.org/x/telemetry v0.0.0-20260717140457-bdb89881bb75 h1:I9ygRooEYoVHV0SRNOSr/KVjTf5EeJ52BuNkVjsP2GU=
golang.org/x/telemetry v0.0.0-20260717140457-bdb89881bb75/go.mod h1:LV7u5Oco+Z/g6XI7PqN+EUUUGGkEcmB1uj2ceI0fOVg=
golang.org/x/term v0.0.0-20201126162022-7de9c90e9dd1/go.mod h1:bj7SfCRtBDWHUb9snDiAeCFNEtKQo2Wmx5Cou7ajbmo=
golang.org/x/term v0.45.0 h1:NwWyBmoJCbfTHpxrWoZ9C6/VxOf7ic219I8xZZFdrf0=
golang.org/x/term v0.45.0/go.mod h1:9aqxs0blBcrm/n0L9QW0aRVD+ktan8ssZromtqJC43w=
golang.org/x/text v0.3.0/go.mod h1:NqM8EUOU14njkJ3fqMW+pc6Ldnwhi/IjpwHt7yyuwOQ=
golang.org/x/text v0.3.3/go.mod h1:5Zoc/QRtKVWzQhOtBMvqHzDpF6irO9z98xDceosuGiQ=
golang.org/x/text v0.3.6/go.mod h1:5Zoc/QRtKVWzQhOtBMvqHzDpF6irO9z98xDceosuGiQ=
golang.org/x/text v0.40.0 h1:Ub2Z6/xjgF1WrYQz2nuITOEegKFtiIy+rieRJ5lHZKs=
golang.org/x/text v0.40.0/go.mod h1:hpnzDAfGV753zIKo+wk3u1bVKCGPbrnF7+7LBF/UHVY=
golang.org/x/time v0.3.0/go.mod h1:tRJNPiyCQ0inRvYxbN9jk5I+vvW/OXSQhTDSoE431IQ=
golang.org/x/time v0.15.0 h1:bbrp8t3bGUeFOx08pvsMYRTCVSMk89u4tKbNOZbp88U=
golang.org/x/time v0.15.0/go.mod h1:Y4YMaQmXwGQZoFaVFk4YpCt4FLQMYKZe9oeV/f4MSno=
golang.org/x/tools v0.0.0-20180917221912-90fa682c2a6e/go.mod h1:n7NCudcB/nEzxVGmLbDWY5pfWTLqBcC2KZ6jyYvM4mQ=
golang.org/x/tools v0.0.0-20200130002326-2f3ba24bd6e7/go.mod h1:TB2adYChydJhpapKDTa4BR/hXlZSLoq2Wpct/0txZ28=
golang.org/x/tools v0.48.0 h1:3+hClM1aLL5mjMKm5ovokw9epgRXPuu2tILgismM6RE=
golang.org/x/tools v0.48.0/go.mod h1:08xX0orndb/F7jJxGDicx061tyd5pcMto75YMAXr6lk=
golang.org/x/xerrors v0.0.0-20191011141410-1b5146add898/go.mod h1:I/5z698sn9Ka8TeJc9MKroUUfqBBauWjQqLJ2OPfmY0=
golang.org/x/xerrors v0.0.0-20191204190536-9bdfabe68543/go.mod h1:I/5z698sn9Ka8TeJc9MKroUUfqBBauWjQqLJ2OPfmY0=
golang.org/x/xerrors v0.0.0-20240903120638-7835f813f4da h1:noIWHXmPHxILtqtCOPIhSt0ABwskkZKjD3bXGnZGpNY=
golang.org/x/xerrors v0.0.0-20240903120638-7835f813f4da/go.mod h1:NDW/Ps6MPRej6fsCIbMTohpP40sJ/P/vI1MoTEGwX90=
golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 h1:B82qJJgjvYKsXS9jeunTOisW56dUokqW/FOteYJJ/yg=
golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2/go.mod h1:deeaetjYA+DHMHg+sMSMI58GrEteJUUzzw7en6TJQcI=
golang.zx2c4.com/wireguard v0.0.0-20260522210424-ecfc5a8d5446 h1:cqHQ3AycTHvM2R7ikgyX57D+XvtcSnGylsLkOVhta/w=
golang.zx2c4.com/wireguard v0.0.0-20260522210424-ecfc5a8d5446/go.mod h1:rpwXGsirqLqN2L0JDJQlwOboGHmptD5ZD6T2VmcqhTw=
gonum.org/v1/gonum v0.17.0 h1:VbpOemQlsSMrYmn7T2OUvQ4dqxQXU+ouZFQsZOx50z4=
gonum.org/v1/gonum v0.17.0/go.mod h1:El3tOrEuMpv2UdMrbNlKEh9vd86bmQ6vqIcDwxEOc1E=
google.golang.org/protobuf v0.0.0-20200109180630-ec00e32a8dfd/go.mod h1:DFci5gLYBciE7Vtevhsrf46CRTquxDuWsQurQQe4oz8=
google.golang.org/protobuf v0.0.0-20200221191635-4d8936d0db64/go.mod h1:kwYJMbMJ01Woi6D6+Kah6886xMZcty6N08ah7+eCXa0=
google.golang.org/protobuf v0.0.0-20200228230310-ab0ca4ff8a60/go.mod h1:cfTl7dwQJ+fmap5saPgwCLgHXTUD7jkjRqWcaiX5VyM=
google.golang.org/protobuf v1.20.1-0.20200309200217-e05f789c0967/go.mod h1:A+miEFZTKqfCUM6K7xSMQL9OKL/b6hQv+e19PK+JZNE=
google.golang.org/protobuf v1.21.0/go.mod h1:47Nbq4nVaFHyn7ilMalzfO3qCViNmqZ2kzikPIcrTAo=
google.golang.org/protobuf v1.22.0/go.mod h1:EGpADcykh3NcUnDUJcl1+ZksZNG86OlYog2l/sGQquU=
google.golang.org/protobuf v1.26.0-rc.1/go.mod h1:jlhhOSvTdKEhbULTjvd4ARK9grFBp09yW+WbY/TyQbw=
google.golang.org/protobuf v1.26.0/go.mod h1:9q0QmTI4eRPtz6boOQmLYwt+qCgq0jsYwAQnmE0givc=
google.golang.org/protobuf v1.36.11 h1:fV6ZwhNocDyBLK0dj+fg8ektcVegBBuEolpbTQyBNVE=
google.golang.org/protobuf v1.36.11/go.mod h1:HTf+CrKn2C3g5S8VImy6tdcUvCska2kB7j23XfzDpco=
gopkg.in/Knetic/govaluate.v3 v3.0.0 h1:18mUyIt4ZlRlFZAAfVetz4/rzlJs9yhN+U02F4u1AOc=
gopkg.in/Knetic/govaluate.v3 v3.0.0/go.mod h1:csKLBORsPbafmSCGTEh3U7Ozmsuq8ZSIlKk1bcqph0E=
gopkg.in/check.v1 v0.0.0-20161208181325-20d25e280405/go.mod h1:Co6ibVJAznAaIkqp8huTwlJQCZ016jof/cbN4VW5Yz0=
gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c h1:Hei/4ADfdWqJk1ZMxUNpqntNwaWcugrBjAiHlqqRiVk=
gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c/go.mod h1:JHkPIbrfpd72SG/EVd6muEfDQjcINNoR0C8j2r3qZ4Q=
gopkg.in/yaml.v2 v2.2.2/go.mod h1:hI93XBmqTisBFMUTm0b8Fm+jr3Dg1NNxqwp+5A1VGuI=
gopkg.in/yaml.v2 v2.2.8/go.mod h1:hI93XBmqTisBFMUTm0b8Fm+jr3Dg1NNxqwp+5A1VGuI=
gopkg.in/yaml.v2 v2.4.0 h1:D8xgwECY7CYvx+Y2n4sBz93Jn9JRvxdiyyo8CTfuKaY=
gopkg.in/yaml.v2 v2.4.0/go.mod h1:RDklbk79AGWmwhnvt/jBztapEOGDOx6ZbXqjP6csGnQ=
gopkg.in/yaml.v3 v3.0.0-20200313102051-9f266ea9e77c/go.mod h1:K4uyk7z7BCEPqu6E+C64Yfv1cQ7kz7rIZviUmN+EgEM=
gopkg.in/yaml.v3 v3.0.0/go.mod h1:K4uyk7z7BCEPqu6E+C64Yfv1cQ7kz7rIZviUmN+EgEM=
gopkg.in/yaml.v3 v3.0.1 h1:fxVm/GzAzEWqLHuvctI91KS9hhNmmWOoWu0XTYJS7CA=
gopkg.in/yaml.v3 v3.0.1/go.mod h1:K4uyk7z7BCEPqu6E+C64Yfv1cQ7kz7rIZviUmN+EgEM=
gvisor.dev/gvisor v0.0.0-20250503011706-39ed1f5ac29c h1:m/r7OM+Y2Ty1sgBQ7Qb27VgIMBW8ZZhT4gLnUyDIhzI=
gvisor.dev/gvisor v0.0.0-20250503011706-39ed1f5ac29c/go.mod h1:3r5CMtNQMKIvBlrmM9xWUNamjKBYPOWyXOjmg5Kts3g=
lukechampine.com/blake3 v1.4.1 h1:I3Smz7gso8w4/TunLKec6K2fn+kyKtDxr/xcQEN84Wg=
lukechampine.com/blake3 v1.4.1/go.mod h1:QFosUxmjB8mnrWFSNwKmvxHpfY72bmD2tQ0kBMM3kwo=
