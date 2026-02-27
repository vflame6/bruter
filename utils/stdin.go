package utils

import (
	"os"
	"runtime"

	"github.com/mattn/go-isatty"
)

// HasStdin returns true if data is being piped to stdin.
func HasStdin() bool {
	if runtime.GOOS == "windows" && (isatty.IsTerminal(os.Stdin.Fd()) || isatty.IsCygwinTerminal(os.Stdin.Fd())) {
		return false
	}
	stat, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	mode := stat.Mode()
	return (mode&os.ModeCharDevice) == 0 || (mode&os.ModeNamedPipe) != 0
}
