//go:build !windows

package app

import "os"

func hasTunnelPrivilege() bool { return os.Geteuid() == 0 }
