//go:build !linux && !windows

package firewallguard

import (
	"context"
	"log/slog"

	"almighty-blocker-unstoppable/internal/logger"
)

type Guard struct {
	log *slog.Logger
}

func New(_ []string, _ []string, _ []string, _ bool) *Guard {
	return &Guard{log: logger.New("firewall-guard")}
}

func (g *Guard) Run(ctx context.Context) {
	g.log.Warn("firewall guard not supported on this platform")
	<-ctx.Done()
}

func (g *Guard) RunOnce() {}
