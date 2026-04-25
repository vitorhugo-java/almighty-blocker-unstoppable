//go:build windows

// Package dnshijack provides DNS configuration protection.
// On Windows it uses netsh to enforce configured DNS servers on active IPv4
// interfaces every 10 seconds.
//
// Java analogy: a @Scheduled(fixedDelay = 10_000) method inside a Spring @Service
// that invokes a shell command to audit and repair the network configuration.
package dnshijack

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"almighty-blocker-unstoppable/internal/logger"
)

// checkInterval is how often we inspect the DNS configuration.
const checkInterval = 10 * time.Second

// Guard periodically verifies that every active network interface uses one of
// the configured DNS servers as primary and restores it when changed.
//
// Java analogy: a ScheduledExecutorService task running a ProcessBuilder command
// on a fixed schedule.
type Guard struct {
	log      *slog.Logger
	desired  []string
	warnOnly bool
	mismatch map[string]bool
}

// New creates a new Guard instance.
func New(desired []string, warnOnly bool) *Guard {
	filtered := make([]string, 0, len(desired))
	for _, server := range desired {
		host := strings.TrimSpace(server)
		if host == "" {
			continue
		}
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		host = strings.Trim(host, "[]")
		if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
			filtered = append(filtered, ip.String())
		}
	}

	if len(filtered) == 0 {
		filtered = []string{"1.1.1.1", "1.0.0.1"}
	}

	return &Guard{log: logger.New("dns-hijack-guard"), desired: filtered, warnOnly: warnOnly, mismatch: map[string]bool{}}
}

// Run starts the protection loop and blocks until ctx is cancelled.
func (g *Guard) Run(ctx context.Context) {
	// Enforce immediately on startup.
	if err := g.enforce(); err != nil {
		g.log.Error("initial DNS enforcement failed", "error", err)
	}

	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := g.enforce(); err != nil {
				g.log.Error("DNS enforcement failed", "error", err)
			}
		}
	}
}

// EnforceOnce applies configured DNS values immediately.
func (g *Guard) EnforceOnce() error {
	return g.enforce()
}

// enforce queries the current DNS configuration for all interfaces and resets
// any that do not use configured DNS values.
func (g *Guard) enforce() error {
	// List all IPv4 interface names using netsh.
	// "netsh interface ipv4 show interfaces" lists active adapters.
	ifaces, err := activeInterfaceNames()
	if err != nil {
		return err
	}

	var failed []string

	for _, iface := range ifaces {
		// Check the DNS server configured on this interface.
		// "netsh interface ip show dns <name>" prints the current DNS servers.
		cmdShow := exec.Command("netsh", "interface", "ip", "show", "dns", "name="+iface)
		hideWindow(cmdShow)
		out, err := cmdShow.Output()
		if err != nil {
			// Non-fatal – continue with other interfaces.
			g.log.Debug("could not read DNS for interface", "interface", iface, "error", err)
			continue
		}

		if primaryDNSIsDesired(string(out), g.desired) {
			if g.mismatch[iface] {
				g.log.Info("DNS restored", "interface", iface)
				g.mismatch[iface] = false
			}
			continue
		}

		if !g.mismatch[iface] {
			g.log.Warn("DNS change detected", "interface", iface)
			g.mismatch[iface] = true
		}
		if g.warnOnly {
			continue
		}

		// Force the primary DNS back using netsh.
		// "static" means we are setting a static address (not DHCP-assigned).
		// This requires the process to be running as SYSTEM or Administrator.
		cmd := exec.Command(
			"netsh", "interface", "ip", "set", "dns",
			"name="+iface, "static", g.desired[0], "primary",
		)
		hideWindow(cmd)
		if setOut, setErr := cmd.CombinedOutput(); setErr != nil {
			g.log.Error("failed to restore DNS",
				"interface", iface,
				"error", setErr,
				"output", strings.TrimSpace(string(setOut)),
			)
			failed = append(failed, iface)
			continue
		}

		for idx, backup := range g.desired[1:] {
			add := exec.Command(
				"netsh", "interface", "ip", "add", "dns",
				"name="+iface,
				"addr="+backup,
				"index="+strconv.Itoa(idx+2),
			)
			hideWindow(add)
			if addOut, addErr := add.CombinedOutput(); addErr != nil {
				g.log.Error("failed to add secondary DNS",
					"interface", iface,
					"dns", backup,
					"error", addErr,
					"output", strings.TrimSpace(string(addOut)),
				)
				failed = append(failed, iface)
			}
		}

		if len(failed) == 0 || failed[len(failed)-1] != iface {
			g.mismatch[iface] = false
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("failed to enforce DNS on interfaces: %s", strings.Join(failed, ", "))
	}
	return nil
}

// primaryDNSIsDesired reports whether a configured DNS server is the first entry
// for an interface by parsing the output of "netsh interface ip show dns".
//
// The output contains a line of the form:
//
//	DNS servers configured through DHCP:  <ip>
//
// or:
//
//	Statically Configured DNS Servers:    <ip>
//
// Subsequent servers appear on their own indented lines.  We locate the first
// "dns server" label line and read the IP that follows the colon on that line.
func primaryDNSIsDesired(output string, desired []string) bool {
	const marker = "dns server"
	for _, line := range strings.Split(output, "\n") {
		// Case-insensitive search: lower-case once per line to avoid allocating
		// a new string for every Contains call.
		lowerLine := strings.ToLower(line)
		if !strings.Contains(lowerLine, marker) {
			continue
		}
		// The first server IP follows the last colon on this label line.
		idx := strings.LastIndex(line, ":")
		if idx == -1 {
			continue
		}
		ip := strings.TrimSpace(line[idx+1:])
		for _, want := range desired {
			if ip == want {
				return true
			}
		}
		return false
	}
	return false
}

// activeInterfaceNames returns the names of all enabled IPv4 network interfaces
// by parsing the output of "netsh interface show interface".
func activeInterfaceNames() ([]string, error) {
	// The output looks like:
	//   Admin State    State          Type             Interface Name
	//   -------------------------------------------------------------------------
	//   Enabled        Connected      Dedicated        Ethernet
	//   Enabled        Connected      Dedicated        Wi-Fi
	cmd := exec.Command("netsh", "interface", "show", "interface")
	hideWindow(cmd)
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var names []string
	for _, line := range strings.Split(string(out), "\n") {
		// Only process lines that describe an "Enabled" and "Connected" interface.
		if !strings.Contains(line, "Enabled") || !strings.Contains(line, "Connected") {
			continue
		}

		// The interface name starts after the last run of spaces following the type column.
		// We split the line into fields and use everything from field index 3 onward.
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		// Rejoin remaining fields in case the interface name contains spaces.
		name := strings.TrimSpace(strings.Join(fields[3:], " "))

		// Skip loopback – no need to set DNS on the loopback adapter itself.
		if strings.EqualFold(name, "Loopback Pseudo-Interface 1") {
			continue
		}
		if strings.Contains(strings.ToLower(name), "zerotier") {
			continue
		}
		names = append(names, name)
	}
	return names, nil
}

func hideWindow(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
}
