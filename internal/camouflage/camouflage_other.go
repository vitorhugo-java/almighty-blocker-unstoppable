//go:build !linux && !windows

// Package camouflage provides process/service name randomisation.
// On platforms other than Linux and Windows this is a no-op because the
// necessary OS-level APIs (prctl on Linux, Windows Registry on Windows) are
// not available.
package camouflage

import "log/slog"

// Randomize is a no-op on unsupported platforms.
func Randomize(serviceName string) {
	slog.Default().With("component", "camouflage").
		Warn("process name randomisation is not supported on this platform")
}
