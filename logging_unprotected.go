//go:build noprotection

package main

import (
	"log/slog"
	"os"
)

// The unprotected (debug) build keeps the normal stderr logger so the
// watchdog/debug terminal shows DNS and firewall activity. The protected build
// ships logging_protected.go instead, which routes all logging to io.Discard so
// the silent GUI-subsystem binary never writes output, however it is launched.
func init() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))
}
