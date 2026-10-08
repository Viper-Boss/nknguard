//go:build !windows

package state

import "os"

func replaceStateFile(source, target string) error { return os.Rename(source, target) }
