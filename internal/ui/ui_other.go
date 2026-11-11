//go:build !windows

package ui

// enableVT tidak diperlukan di non-Windows (ANSI sudah didukung).
func enableVT() {}
