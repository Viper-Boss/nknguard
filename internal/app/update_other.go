//go:build !linux

package app

import (
	"errors"
	"github.com/Viper-Boss/nknguard/internal/config"
)

func updateKind() string                 { return "linux" }
func updateSupported(config.Config) bool { return false }
func launchUpdate(config.Config, string) error {
	return errors.New("NAS package updates require Linux")
}
func ApplyUpdate(config.Config, string) error { return errors.New("NAS package updates require Linux") }
