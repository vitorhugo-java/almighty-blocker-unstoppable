//go:build !linux && !windows

// Package dnshijack provides DNS hijack protection.
// On platforms other than Linux and Windows this is a no-op because the
// OS-specific APIs needed to inspect and override DNS settings are not
// available.
package dnshijack

import (
	"context"
	"log/slog"

	"almighty-blocker-unstoppable/internal/logger"
)

// Guard is a no-op DNS hijack guard for unsupported operating systems.
type Guard struct {
	log *slog.Logger
}

// New creates a new (no-op) Guard instance.
func New() *Guard {
	return &Guard{log: logger.New("dns-hijack-guard")}
}

// Run logs a warning and returns immediately when ctx is cancelled.
// No DNS enforcement is performed on unsupported platforms.
func (g *Guard) Run(ctx context.Context) {
	g.log.Warn("DNS hijack protection is not supported on this platform")
	<-ctx.Done()
}
