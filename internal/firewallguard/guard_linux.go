//go:build linux

package firewallguard

import (
	"context"
	"log/slog"
	"os/exec"
	"strings"
	"time"

	"almighty-blocker-unstoppable/internal/logger"
)

const (
	ipsetName     = "almighty_block_ips"
	checkInterval = 15 * time.Second
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

	if g.warnOnly {
		if ok := g.rulesExist(); !ok {
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
	g.applyLinuxRules(ips)
}

func (g *Guard) rulesExist() bool {
	if err := exec.Command("ipset", "list", ipsetName).Run(); err != nil {
		return false
	}
	if err := exec.Command("iptables", "-C", "OUTPUT", "-m", "set", "--match-set", ipsetName, "dst", "-j", "REJECT").Run(); err != nil {
		return false
	}
	return true
}

func (g *Guard) applyLinuxRules(ips []string) {
	if out, err := exec.Command("ipset", "create", ipsetName, "hash:ip", "-exist").CombinedOutput(); err != nil {
		g.log.Error("failed to create ipset", "error", err, "output", strings.TrimSpace(string(out)))
		return
	}

	if out, err := exec.Command("ipset", "flush", ipsetName).CombinedOutput(); err != nil {
		g.log.Error("failed to flush ipset", "error", err, "output", strings.TrimSpace(string(out)))
		return
	}

	for _, ip := range ips {
		if out, err := exec.Command("ipset", "add", ipsetName, ip, "-exist").CombinedOutput(); err != nil {
			g.log.Error("failed to add ipset entry", "ip", ip, "error", err, "output", strings.TrimSpace(string(out)))
		}
	}

	if err := exec.Command("iptables", "-C", "OUTPUT", "-m", "set", "--match-set", ipsetName, "dst", "-j", "REJECT").Run(); err != nil {
		if out, addErr := exec.Command("iptables", "-A", "OUTPUT", "-m", "set", "--match-set", ipsetName, "dst", "-j", "REJECT").CombinedOutput(); addErr != nil {
			g.log.Error("failed to add iptables rule", "error", addErr, "output", strings.TrimSpace(string(out)))
		}
	}
}
