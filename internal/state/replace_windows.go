//go:build windows

package state

import (
	"errors"
	"os"
	"time"

	"golang.org/x/sys/windows"
)

// Indexers and scanners can briefly hold handles without FILE_SHARE_DELETE.
// Retry the same rename for at most one second; never remove the old file.
func replaceStateFile(source, target string) error {
	deadline := time.Now().Add(time.Second)
	for {
		err := os.Rename(source, target)
		if err == nil || time.Now().After(deadline) || !(errors.Is(err, windows.ERROR_ACCESS_DENIED) || errors.Is(err, windows.ERROR_SHARING_VIOLATION) || errors.Is(err, windows.ERROR_LOCK_VIOLATION)) {
			return err
		}
		time.Sleep(40 * time.Millisecond)
	}
}
