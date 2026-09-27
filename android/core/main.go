// Command nkgcore is the protocol core of the NKNGuard Android app.
//
// The app ships it as lib/<abi>/libnkgcore.so so that Android installs it as
// an executable in the app's native library directory, starts it with
// ProcessBuilder, and talks to it over standard input and output (see
// internal/mobile). Standard error carries the log. The process exits when
// its standard input closes, which is what happens if the app dies, and the
// VPN interface it holds closes with it.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/Viper-Boss/nknguard/internal/app"
	"github.com/Viper-Boss/nknguard/internal/mobile"
	"github.com/Viper-Boss/nknguard/pkg/usagestats"
)

func main() {
	stateDir := flag.String("state-dir", "", "private directory for non-secret state")
	fdSocket := flag.String("fd-socket", "", "Unix socket on which the app hands over the VPN file descriptor")
	level := flag.String("log-level", "info", "debug, info, warn or error")
	version := flag.Bool("version", false, "print the version and exit")
	flag.Parse()
	if *version {
		fmt.Println(app.Version)
		return
	}
	if *stateDir == "" || *fdSocket == "" {
		fmt.Fprintln(os.Stderr, "usage: libnkgcore.so --state-dir DIR --fd-socket PATH")
		os.Exit(2)
	}
	if err := run(*stateDir, *fdSocket, *level); err != nil {
		fmt.Fprintln(os.Stderr, "nkgcore:", err)
		os.Exit(1)
	}
}

func run(stateDir, fdSocket, level string) error {
	// Standard output is the protocol channel. Keep a private copy of it and
	// point file descriptor 1 at the log, so a stray print from a library can
	// never corrupt a JSON line.
	protocolFD, err := unix.Dup(1)
	if err != nil {
		return err
	}
	if err := unix.Dup3(2, 1, 0); err != nil {
		return err
	}
	protocolOut := os.NewFile(uintptr(protocolFD), "protocol")

	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(fdSocket), 0o700); err != nil {
		return err
	}
	mobile.InstallResolver()
	logger, ring := app.NewLogger(os.Stderr, level)
	receiver, err := mobile.ListenFD(fdSocket)
	if err != nil {
		return err
	}
	defer receiver.Close()

	agent := &mobile.Agent{
		StateDir: stateDir,
		Secrets:  mobile.NewSecretStore(),
		Logger:   logger,
		Logs:     ring,
		// Anonymous active-installation count; the app shows it and its
		// switch (see pkg/usagestats).
		UsageChain: usagestats.NewNKNChain,
		OpenTUN: func(ctx context.Context, token string) (tun.Device, error) {
			fd, err := receiver.Receive(ctx, token)
			if err != nil {
				return nil, err
			}
			device, _, err := tun.CreateUnmonitoredTUNFromFD(fd)
			if err != nil {
				_ = unix.Close(fd)
				return nil, err
			}
			return device, nil
		},
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	go func() {
		// A signal must still end the process even while a read on standard
		// input is blocked.
		<-ctx.Done()
		_ = os.Stdin.Close()
	}()
	logger.Info("core started", "component", "app", "version", app.Version)
	return agent.Serve(ctx, os.Stdin, protocolOut)
}
