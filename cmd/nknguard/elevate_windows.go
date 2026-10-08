//go:build windows

package main

import (
	"fmt"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// SHELLEXECUTEINFOW keeps its native alignment on both Windows architectures.
type shellExecuteInfo struct {
	Size, Mask                        uint32
	Window                            uintptr
	Verb, File, Parameters, Directory *uint16
	Show                              int32
	Instance, IDList                  uintptr
	Class                             *uint16
	ClassKey                          uintptr
	HotKey                            uint32
	Icon                              uintptr
	Process                           windows.Handle
}

func runElevated(executable, configPath string) (windows.Handle, error) {
	return runElevatedCommand(executable, configPath, "up")
}

func runElevatedCommand(executable, configPath, command string) (windows.Handle, error) {
	if command != "up" && command != "cleanup" {
		return 0, fmt.Errorf("不支持的后台操作")
	}
	verb, _ := syscall.UTF16PtrFromString("runas")
	file, err := syscall.UTF16PtrFromString(executable)
	if err != nil {
		return 0, err
	}
	params, err := syscall.UTF16PtrFromString("--config " + syscall.EscapeArg(configPath) + " " + command)
	if err != nil {
		return 0, err
	}
	info := shellExecuteInfo{Mask: 0x40 | 0x100, Verb: verb, File: file, Parameters: params, Show: 0}
	info.Size = uint32(unsafe.Sizeof(info))
	shell := syscall.NewLazyDLL("shell32.dll").NewProc("ShellExecuteExW")
	ok, _, callErr := shell.Call(uintptr(unsafe.Pointer(&info)))
	runtime.KeepAlive(info)
	if ok == 0 {
		return 0, fmt.Errorf("管理员授权未完成: %w", callErr)
	}
	if info.Process == 0 {
		return 0, fmt.Errorf("后台启动未返回进程句柄")
	}
	return info.Process, nil
}
