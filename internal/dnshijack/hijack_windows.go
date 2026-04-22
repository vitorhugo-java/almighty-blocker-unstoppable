//go:build windows

// Package dnshijack provides DNS hijack protection.
// On Windows it uses netsh to detect and restore 127.0.0.1 as the primary DNS
// on every active IPv4 interface every 10 seconds.
//
// Java analogy: a @Scheduled(fixedDelay = 10_000) method inside a Spring @Service
// that invokes a shell command to audit and repair the network configuration.
package dnshijack

import (
	"context"
	"log/slog"
	"os/exec"
	"strings"
	"time"

	"almighty-blocker-unstoppable/internal/logger"
)

// checkInterval is how often we inspect the DNS configuration.
const checkInterval = 10 * time.Second

// Guard periodically verifies that every active network interface uses 127.0.0.1
// as its primary DNS server and restores it if another process changes it.
//
// Java analogy: a ScheduledExecutorService task running a ProcessBuilder command
// on a fixed schedule.
type Guard struct {
	log *slog.Logger
}

// New creates a new Guard instance.
func New() *Guard {
	return &Guard{log: logger.New("dns-hijack-guard")}
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

// enforce queries the current DNS configuration for all interfaces and resets
// any that do not use 127.0.0.1 as the primary server.
func (g *Guard) enforce() error {
	// List all IPv4 interface names using netsh.
	// "netsh interface ipv4 show interfaces" lists active adapters.
	ifaces, err := activeInterfaceNames()
	if err != nil {
		return err
	}

	for _, iface := range ifaces {
		// Check the DNS server configured on this interface.
		// "netsh interface ip show dns <name>" prints the current DNS servers.
		out, err := exec.Command("netsh", "interface", "ip", "show", "dns", "name="+iface).Output()
		if err != nil {
			// Non-fatal – continue with other interfaces.
			g.log.Debug("could not read DNS for interface", "interface", iface, "error", err)
			continue
		}

		// If 127.0.0.1 is already the primary entry, nothing to do.
		if strings.Contains(string(out), "127.0.0.1") {
			continue
		}

		g.log.Warn("DNS hijack detected – restoring 127.0.0.1", "interface", iface)

		// Force the primary DNS back to 127.0.0.1 using netsh.
		// "static" means we are setting a static address (not DHCP-assigned).
		// This requires the process to be running as SYSTEM or Administrator.
		cmd := exec.Command(
			"netsh", "interface", "ip", "set", "dns",
			"name="+iface, "static", "127.0.0.1", "primary",
		)
		if setOut, setErr := cmd.CombinedOutput(); setErr != nil {
			g.log.Error("failed to restore DNS",
				"interface", iface,
				"error", setErr,
				"output", strings.TrimSpace(string(setOut)),
			)
		}
	}
	return nil
}

// activeInterfaceNames returns the names of all enabled IPv4 network interfaces
// by parsing the output of "netsh interface show interface".
func activeInterfaceNames() ([]string, error) {
	// The output looks like:
	//   Admin State    State          Type             Interface Name
	//   -------------------------------------------------------------------------
	//   Enabled        Connected      Dedicated        Ethernet
	//   Enabled        Connected      Dedicated        Wi-Fi
	out, err := exec.Command("netsh", "interface", "show", "interface").Output()
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
		names = append(names, name)
	}
	return names, nil
}
