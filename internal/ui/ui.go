// Package ui menyediakan warna output terminal untuk CLI CSIX.
package ui

import "os"

var enabled bool

// Setup mengaktifkan warna output (otomatis mati bila NO_COLOR ter-set).
func Setup() {
	if os.Getenv("NO_COLOR") != "" {
		return
	}
	enableVT()
	enabled = true
}

// Wrap membungkus teks dengan kode warna ANSI.
func Wrap(code, s string) string {
	if !enabled {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

// Kode warna umum.
const (
	Red    = "31"
	Green  = "32"
	Yellow = "33"
	Cyan   = "36"
	Gray   = "90"
	Bold   = "1"
)
