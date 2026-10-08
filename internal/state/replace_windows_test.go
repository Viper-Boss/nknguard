//go:build windows

package state

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestReplaceRetriesTemporaryWindowsSharingConflict(t *testing.T) {
	dir := t.TempDir()
	target, source := filepath.Join(dir, "state.json"), filepath.Join(dir, ".new")
	if err := os.WriteFile(target, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	name, _ := windows.UTF16PtrFromString(target)
	handle, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { time.Sleep(120 * time.Millisecond); _ = windows.CloseHandle(handle); close(done) }()
	err = replaceStateFile(source, target)
	<-done
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(target)
	if err != nil || string(raw) != "new" {
		t.Fatalf("replacement lost: %s %v", raw, err)
	}
}
