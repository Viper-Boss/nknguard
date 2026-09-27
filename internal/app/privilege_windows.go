//go:build windows

package app

import "golang.org/x/sys/windows"

func hasTunnelPrivilege() bool { return windows.GetCurrentProcessToken().IsElevated() }
