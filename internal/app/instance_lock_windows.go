//go:build windows

package app

import (
	"golang.org/x/sys/windows"
	"os"
)

func lockInstanceFile(f *os.File) error {
	var overlap windows.Overlapped
	return windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &overlap)
}
