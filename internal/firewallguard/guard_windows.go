//go:build windows

package firewallguard

import (
	"context"
	"log/slog"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"almighty-blocker-unstoppable/internal/logger"
)

const (
	windowsRulePrefix    = "Almighty Blocker Outbound"
	windowsTorRulePrefix = "Almighty Blocker Tor Outbound"
	checkInterval        = 15 * time.Second
	chunkSize            = 25
	// initialStaleSweep bounds first-run cleanup of stale numbered rules from
	// previous process lifetimes before in-memory chunk history is available.
	initialStaleSweep = 200
)

type Guard struct {
	log         *slog.Logger
	mu          sync.RWMutex
	reconcileMu sync.Mutex
	lastChunks  map[string]int
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
		lastChunks:  map[string]int{},
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
	torChunks := splitIPChunksByFamily(torIPs, chunkSize)
	otherChunks := splitIPChunksByFamily(otherIPs, chunkSize)

	// reconcile reads each rule's current remoteip set and compares it to the
	// desired one. In enforcement mode it rewrites only the rules that drifted
	// (instead of blindly re-adding every rule each tick); in warn-only mode it
	// reports drift without modifying anything.
	otherDrift := g.reconcile(windowsRulePrefix, otherChunks)
	torDrift := g.reconcile(windowsTorRulePrefix, torChunks)
	drift := otherDrift || torDrift

	if g.warnOnly {
		if drift {
			if !g.missing {
				g.log.Warn("firewall change detected")
				g.missing = true
			}
		} else if g.missing {
			g.log.Info("firewall rules restored")
			g.missing = false
		}
		return
	}

	if drift {
		g.log.Warn("firewall change detected")
	}
	g.missing = false
}

// reconcile compares every chunk rule against the desired remote-IP set and,
// when enforcing, repairs only the rules that drifted. It returns whether any
// drift (missing rule or changed remoteip set) was observed.
func (g *Guard) reconcile(prefix string, chunks [][]string) bool {
	drift := false
	for idx, chunk := range chunks {
		ruleName := prefix + " #" + strconv.Itoa(idx+1)
		actual, exists := g.ruleRemoteIPs(ruleName)
		if exists && setsEqual(actual, ipSet(chunk)) {
			continue
		}
		drift = true
		if g.warnOnly {
			continue
		}
		g.writeRule(ruleName, chunk)
	}
	if !g.warnOnly {
		g.cleanupStaleChunks(prefix, len(chunks))
	}
	return drift
}

// ruleRemoteIPs returns the normalized set of remote IPs currently configured on
// the named firewall rule. The bool is false when the rule does not exist.
func (g *Guard) ruleRemoteIPs(ruleName string) (map[string]struct{}, bool) {
	cmd := exec.Command("netsh", "advfirewall", "firewall", "show", "rule", "name="+ruleName, "verbose")
	hideWindow(cmd)
	out, err := cmd.CombinedOutput()
	if err != nil {
		// Non-zero exit means no rule matched the name.
		return nil, false
	}

	set := make(map[string]struct{})
	capturing := false
	for _, line := range strings.Split(string(out), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "RemoteIP:") {
			capturing = true
			addRuleIPs(set, strings.TrimSpace(strings.TrimPrefix(trimmed, "RemoteIP:")))
			continue
		}
		if capturing {
			// netsh wraps multi-value fields onto indented continuation lines
			// (which carry no column-0 label). Indentation — not the presence of
			// ':' — distinguishes them, so IPv6 values are handled correctly.
			if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
				addRuleIPs(set, trimmed)
				continue
			}
			capturing = false
		}
	}
	return set, true
}

// writeRule replaces a single numbered chunk rule with the desired remote IPs.
func (g *Guard) writeRule(ruleName string, chunk []string) {
	cmdDel := exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name="+ruleName)
	hideWindow(cmdDel)
	_ = cmdDel.Run()

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
	hideWindow(cmd)
	if out, err := cmd.CombinedOutput(); err != nil {
		g.log.Error("failed to apply firewall rule", "rule", ruleName, "error", err, "output", strings.TrimSpace(string(out)))
	}
}

// cleanupStaleChunks removes numbered rules left over from a previous refresh
// that used more chunks than the current one.
func (g *Guard) cleanupStaleChunks(prefix string, current int) {
	previous, known := g.lastChunks[prefix]
	if !known {
		previous = current + initialStaleSweep
	}
	for _, i := range staleChunkIndexes(previous, current) {
		ruleName := prefix + " #" + strconv.Itoa(i)
		cmd := exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name="+ruleName)
		hideWindow(cmd)
		_ = cmd.Run()
	}
	g.lastChunks[prefix] = current
}

// addRuleIPs splits a (possibly comma-separated) netsh remoteip value and adds
// each normalized IP to set.
func addRuleIPs(set map[string]struct{}, value string) {
	for _, part := range strings.Split(value, ",") {
		if ip := normalizeRuleIP(part); ip != "" {
			set[ip] = struct{}{}
		}
	}
}

// normalizeRuleIP canonicalizes a single netsh remoteip token so that values
// such as "1.2.3.4/32" and "1.2.3.4" (or differently-cased IPv6) compare equal.
func normalizeRuleIP(token string) string {
	token = strings.TrimSpace(token)
	if token == "" {
		return ""
	}
	// Strip single-host CIDR suffixes that netsh appends to literal IPs.
	if i := strings.IndexByte(token, '/'); i >= 0 {
		if suffix := token[i+1:]; suffix == "32" || suffix == "128" {
			token = token[:i]
		}
	}
	if ip := net.ParseIP(token); ip != nil {
		return ip.String()
	}
	return token
}

// ipSet builds a normalized set from a desired chunk of IPs.
func ipSet(items []string) map[string]struct{} {
	set := make(map[string]struct{}, len(items))
	for _, item := range items {
		if ip := normalizeRuleIP(item); ip != "" {
			set[ip] = struct{}{}
		}
	}
	return set
}

func setsEqual(a, b map[string]struct{}) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if _, ok := b[k]; !ok {
			return false
		}
	}
	return true
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

// createNoWindow (CREATE_NO_WINDOW) keeps every netsh invocation from ever
// allocating a console, so the protected GUI build performs its firewall checks
// without flashing a terminal window.
const createNoWindow = 0x08000000

func hideWindow(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
}
