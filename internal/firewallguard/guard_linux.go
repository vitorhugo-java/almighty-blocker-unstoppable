//go:build linux

package firewallguard

import (
	"context"
	"log/slog"
	"os/exec"
	"strings"
	"sync"
	"time"

	"almighty-blocker-unstoppable/internal/logger"
)

const (
	ipsetName      = "almighty_block_ips"
	torIPSetName   = "almighty_block_tor_ips"
	checkInterval  = 15 * time.Second
	torRuleComment = "almighty-blocker-tor"
)

type Guard struct {
	log         *slog.Logger
	mu          sync.RWMutex
	reconcileMu sync.Mutex
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

func (g *Guard) SetTorEntryIPs(torEntryIPs []string) {
	g.mu.Lock()
	g.torEntryIPs = mergeIPs(torEntryIPs)
	g.mu.Unlock()
}

func (g *Guard) reconcileOnce() {
	g.reconcileMu.Lock()
	defer g.reconcileMu.Unlock()

	g.mu.RLock()
	torIPs := append([]string(nil), g.torEntryIPs...)
	g.mu.RUnlock()

	resolved := resolveDomains(g.domains, g.dnsServers)
	otherIPs := mergeIPs(g.manualIPs, resolved)

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
	g.applyLinuxRules(torIPs, otherIPs)
}

func (g *Guard) rulesExist() bool {
	if err := exec.Command("ipset", "list", ipsetName).Run(); err != nil {
		return false
	}
	if err := exec.Command("ipset", "list", torIPSetName).Run(); err != nil {
		return false
	}
	if err := exec.Command("iptables", "-C", "OUTPUT", "-m", "set", "--match-set", ipsetName, "dst", "-j", "REJECT").Run(); err != nil {
		return false
	}
	if err := exec.Command("iptables", "-C", "OUTPUT", "-m", "comment", "--comment", torRuleComment, "-m", "set", "--match-set", torIPSetName, "dst", "-j", "REJECT").Run(); err != nil {
		return false
	}
	return true
}

func (g *Guard) applyLinuxRules(torIPs []string, otherIPs []string) {
	applySet := func(setName string, ips []string) bool {
		if out, err := exec.Command("ipset", "create", setName, "hash:ip", "-exist").CombinedOutput(); err != nil {
			g.log.Error("failed to create ipset", "set", setName, "error", err, "output", strings.TrimSpace(string(out)))
			return false
		}
		if out, err := exec.Command("ipset", "flush", setName).CombinedOutput(); err != nil {
			g.log.Error("failed to flush ipset", "set", setName, "error", err, "output", strings.TrimSpace(string(out)))
			return false
		}
		for _, ip := range ips {
			if out, err := exec.Command("ipset", "add", setName, ip, "-exist").CombinedOutput(); err != nil {
				g.log.Error("failed to add ipset entry", "set", setName, "ip", ip, "error", err, "output", strings.TrimSpace(string(out)))
			}
		}
		return true
	}

	if ok := applySet(ipsetName, otherIPs); !ok {
		return
	}
	if ok := applySet(torIPSetName, torIPs); !ok {
		return
	}

	if err := exec.Command("iptables", "-C", "OUTPUT", "-m", "set", "--match-set", ipsetName, "dst", "-j", "REJECT").Run(); err != nil {
		if out, addErr := exec.Command("iptables", "-A", "OUTPUT", "-m", "set", "--match-set", ipsetName, "dst", "-j", "REJECT").CombinedOutput(); addErr != nil {
			g.log.Error("failed to add iptables rule", "set", ipsetName, "error", addErr, "output", strings.TrimSpace(string(out)))
		}
	}

	if err := exec.Command("iptables", "-C", "OUTPUT", "-m", "comment", "--comment", torRuleComment, "-m", "set", "--match-set", torIPSetName, "dst", "-j", "REJECT").Run(); err == nil {
		return
	}

	if out, err := exec.Command("iptables", "-A", "OUTPUT", "-m", "comment", "--comment", torRuleComment, "-m", "set", "--match-set", torIPSetName, "dst", "-j", "REJECT").CombinedOutput(); err != nil {
		g.log.Error("failed to add tor iptables rule", "set", torIPSetName, "error", err, "output", strings.TrimSpace(string(out)))
	}
}
