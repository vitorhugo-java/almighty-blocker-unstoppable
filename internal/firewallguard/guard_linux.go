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
	ipsetName6     = "almighty_block_ips6"
	torIPSetName   = "almighty_block_tor_ips"
	torIPSetName6  = "almighty_block_tor_ips6"
	checkInterval  = 15 * time.Second
	torRuleComment = "almighty-blocker-tor"
)

// linuxFamily bundles the per-address-family tooling so that the same
// reconciliation logic can enforce IPv4 (iptables/inet ipset) and IPv6
// (ip6tables/inet6 ipset) without duplicating code. Without the IPv6 family,
// IPv6 Tor guard and manual IPs would be fetched but never actually blocked.
type linuxFamily struct {
	iptables  string // "iptables" or "ip6tables"
	inet      string // ipset family: "inet" or "inet6"
	manualSet string
	torSet    string
}

func linuxFamilies() []linuxFamily {
	return []linuxFamily{
		{iptables: "iptables", inet: "inet", manualSet: ipsetName, torSet: torIPSetName},
		{iptables: "ip6tables", inet: "inet6", manualSet: ipsetName6, torSet: torIPSetName6},
	}
}

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

	// Domain entries in blockAddress are filtered at DNS level (Cloudflare
	// family DoH), not here: resolving them over plaintext :53 was hijackable
	// and risked blocking shared/CDN IPs. Only literal IPs are firewalled.
	otherIPs := mergeIPs(g.manualIPs)

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
	for _, fam := range linuxFamilies() {
		if err := exec.Command("ipset", "list", fam.manualSet).Run(); err != nil {
			return false
		}
		if err := exec.Command("ipset", "list", fam.torSet).Run(); err != nil {
			return false
		}
		if err := exec.Command(fam.iptables, "-C", "OUTPUT", "-m", "set", "--match-set", fam.manualSet, "dst", "-j", "REJECT").Run(); err != nil {
			return false
		}
		if err := exec.Command(fam.iptables, "-C", "OUTPUT", "-m", "comment", "--comment", torRuleComment, "-m", "set", "--match-set", fam.torSet, "dst", "-j", "REJECT").Run(); err != nil {
			return false
		}
	}
	return true
}

func (g *Guard) applyLinuxRules(torIPs []string, otherIPs []string) {
	torV4, torV6 := splitIPsByFamily(torIPs)
	otherV4, otherV6 := splitIPsByFamily(otherIPs)

	manualByFamily := map[string][]string{"inet": otherV4, "inet6": otherV6}
	torByFamily := map[string][]string{"inet": torV4, "inet6": torV6}

	for _, fam := range linuxFamilies() {
		if !g.applySet(fam.manualSet, fam.inet, manualByFamily[fam.inet]) {
			continue
		}
		if !g.applySet(fam.torSet, fam.inet, torByFamily[fam.inet]) {
			continue
		}
		g.ensureRejectRule(fam.iptables, fam.manualSet, nil)
		g.ensureRejectRule(fam.iptables, fam.torSet, []string{"-m", "comment", "--comment", torRuleComment})
	}
}

// applySet creates (idempotently) and repopulates an ipset of the given family
// with the desired IPs. Returns false when the set itself could not be
// created/flushed, so the caller skips adding a rule that would never match.
func (g *Guard) applySet(setName string, inet string, ips []string) bool {
	if out, err := exec.Command("ipset", "create", setName, "hash:ip", "family", inet, "-exist").CombinedOutput(); err != nil {
		g.log.Error("failed to create ipset", "set", setName, "family", inet, "error", err, "output", strings.TrimSpace(string(out)))
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

// ensureRejectRule appends an OUTPUT REJECT rule for the named set if an
// identical rule is not already present. extra carries any leading match
// arguments (e.g. the Tor comment) so the check and add stay in sync.
func (g *Guard) ensureRejectRule(iptables string, setName string, extra []string) {
	match := append([]string{}, extra...)
	match = append(match, "-m", "set", "--match-set", setName, "dst", "-j", "REJECT")

	check := append([]string{"-C", "OUTPUT"}, match...)
	if err := exec.Command(iptables, check...).Run(); err == nil {
		return
	}

	add := append([]string{"-A", "OUTPUT"}, match...)
	if out, err := exec.Command(iptables, add...).CombinedOutput(); err != nil {
		g.log.Error("failed to add iptables rule", "cmd", iptables, "set", setName, "error", err, "output", strings.TrimSpace(string(out)))
	}
}
