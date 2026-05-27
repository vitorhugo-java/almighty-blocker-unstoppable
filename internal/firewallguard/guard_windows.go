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

	resolved := resolveDomains(g.domains, g.dnsServers)
	otherIPs := mergeIPs(g.manualIPs, resolved)
	torChunks := splitIPChunksByFamily(torIPs, chunkSize)
	otherChunks := splitIPChunksByFamily(otherIPs, chunkSize)

	if g.warnOnly {
		if ok := g.rulesExist(windowsRulePrefix, otherChunks) && g.rulesExist(windowsTorRulePrefix, torChunks); !ok {
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
	g.applyWindowsRules(windowsRulePrefix, otherChunks)
	g.applyWindowsRules(windowsTorRulePrefix, torChunks)
}

func (g *Guard) rulesExist(prefix string, chunks [][]string) bool {
	for idx := range chunks {
		ruleName := prefix + " #" + strconv.Itoa(idx+1)
		cmd := exec.Command("netsh", "advfirewall", "firewall", "show", "rule", "name="+ruleName)
		hideWindow(cmd)
		if err := cmd.Run(); err != nil {
			return false
		}
	}
	return true
}

func (g *Guard) applyWindowsRules(prefix string, chunks [][]string) {
	for idx, chunk := range chunks {
		ruleName := prefix + " #" + strconv.Itoa(idx+1)
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

	previous, known := g.lastChunks[prefix]
	if !known {
		previous = len(chunks) + initialStaleSweep
	}

	// Remove stale chunk rules left from previous refreshes.
	for _, i := range staleChunkIndexes(previous, len(chunks)) {
		ruleName := prefix + " #" + strconv.Itoa(i)
		cmd := exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name="+ruleName)
		hideWindow(cmd)
		_ = cmd.Run()
	}
	g.lastChunks[prefix] = len(chunks)
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

func hideWindow(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
}
