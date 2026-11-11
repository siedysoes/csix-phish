//go:build windows

package ui

import (
	"os"
	"syscall"
	"unsafe"
)

// enableVT mengaktifkan Virtual Terminal Processing agar ANSI berjalan di
// console Windows 10+ (cmd.exe, PowerShell 5.1, Windows Terminal).
func enableVT() {
	k32 := syscall.NewLazyDLL("kernel32.dll")
	getMode := k32.NewProc("GetConsoleMode")
	setMode := k32.NewProc("SetConsoleMode")
	h := syscall.Handle(os.Stdout.Fd())
	var mode uint32
	r, _, _ := getMode.Call(uintptr(h), uintptr(unsafe.Pointer(&mode)))
	if r != 0 {
		setMode.Call(uintptr(h), uintptr(mode|0x0004)) // ENABLE_VIRTUAL_TERMINAL_PROCESSING
	}
}
