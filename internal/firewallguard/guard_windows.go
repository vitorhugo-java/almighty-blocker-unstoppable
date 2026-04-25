//go:build windows

package firewallguard

import (
	"context"
	"log/slog"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"almighty-blocker-unstoppable/internal/logger"
)

const (
	windowsRulePrefix = "Almighty Blocker Outbound"
	checkInterval     = 15 * time.Second
	chunkSize         = 25
)

type Guard struct {
	log         *slog.Logger
	torEntryIPs []string
	domains     []string
	manualIPs   []string
	dnsServers  []string
	warnOnly    bool
	missing     bool
}

func New(torEntryIPs []string, blockAddress []string, dnsServers []string, warnOnly bool) *Guard {
	domains, manualIPs := parseBlockAddress(blockAddress)
	return &Guard{
		log:         logger.New("firewall-guard"),
		torEntryIPs: mergeIPs(torEntryIPs),
		domains:     domains,
		manualIPs:   manualIPs,
		dnsServers:  dnsServers,
		warnOnly:    warnOnly,
	}
}

func (g *Guard) Run(ctx context.Context) {
	g.reconcileOnce()

	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			g.reconcileOnce()
		}
	}
}

func (g *Guard) RunOnce() {
	g.reconcileOnce()
}

func (g *Guard) reconcileOnce() {
	resolved := resolveDomains(g.domains, g.dnsServers)
	ips := mergeIPs(g.torEntryIPs, g.manualIPs, resolved)
	chunks := splitIPChunksByFamily(ips, chunkSize)

	if g.warnOnly {
		if ok := g.rulesExist(chunks); !ok {
			if !g.missing {
				g.log.Warn("firewall rules missing or changed")
				g.missing = true
			}
		} else if g.missing {
			g.log.Info("firewall rules restored")
			g.missing = false
		}
		return
	}

	g.missing = false
	g.applyWindowsRules(chunks)
}

func (g *Guard) rulesExist(chunks [][]string) bool {
	for idx := range chunks {
		ruleName := windowsRulePrefix + " #" + strconv.Itoa(idx+1)
		cmd := exec.Command("netsh", "advfirewall", "firewall", "show", "rule", "name="+ruleName)
		if err := cmd.Run(); err != nil {
			return false
		}
	}
	return true
}

func (g *Guard) applyWindowsRules(chunks [][]string) {
	for idx, chunk := range chunks {
		ruleName := windowsRulePrefix + " #" + strconv.Itoa(idx+1)
		_ = exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name="+ruleName).Run()

		remote := strings.Join(chunk, ",")
		cmd := exec.Command(
			"netsh", "advfirewall", "firewall", "add", "rule",
			"name="+ruleName,
			"dir=out",
			"action=block",
			"enable=yes",
			"profile=any",
			"remoteip="+remote,
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			g.log.Error("failed to apply firewall rule", "rule", ruleName, "error", err, "output", strings.TrimSpace(string(out)))
		}
	}

	// Remove any extra stale chunk rules from previous runs.
	for i := len(chunks) + 1; i < len(chunks)+20; i++ {
		ruleName := windowsRulePrefix + " #" + strconv.Itoa(i)
		cmd := exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name="+ruleName)
		_ = cmd.Run()
	}
}

func splitIPChunksByFamily(in []string, size int) [][]string {
	if len(in) == 0 || size <= 0 {
		return nil
	}

	v4 := make([]string, 0, len(in))
	v6 := make([]string, 0, len(in))
	for _, item := range in {
		ip := net.ParseIP(strings.TrimSpace(item))
		if ip == nil {
			continue
		}
		if ip.To4() != nil {
			v4 = append(v4, ip.String())
			continue
		}
		v6 = append(v6, ip.String())
	}

	chunks := splitChunks(v4, size)
	chunks = append(chunks, splitChunks(v6, size)...)
	return chunks
}
