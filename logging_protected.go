//go:build !noprotection

package main

import (
	"io"
	"log"
	"log/slog"
)

// The protected production build is linked as a Windows GUI-subsystem binary
// (see cmd/build: -H windowsgui) and must run completely silently: no terminal
// window and no log output, however it is launched (double-click, service, …).
//
// Routing both the standard logger and the slog default handler to io.Discard
// guarantees nothing is ever written, independent of the absence of a console.
// The unprotected build ships logging_unprotected.go instead, which keeps the
// normal stderr logger so the watchdog/debug terminal shows firewall and network
// activity as before.
func init() {
	log.SetOutput(io.Discard)
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
}
