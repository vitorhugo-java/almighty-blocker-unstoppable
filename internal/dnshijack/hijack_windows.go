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
	log       *slog.Logger
	desiredV4 []string
	desiredV6 []string
	warnOnly  bool
	mismatch  map[string]bool
}

// New creates a new Guard instance.
func New(desired []string, warnOnly bool) *Guard {
	v4, v6 := splitDesiredServers(desired)
	if len(v4) == 0 && len(v6) == 0 {
		v4 = []string{"1.1.1.1", "1.0.0.1"}
	}

	return &Guard{
		log:       logger.New("dns-hijack-guard"),
		desiredV4: v4,
		desiredV6: v6,
		warnOnly:  warnOnly,
		mismatch:  map[string]bool{},
	}
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
		currentV4, err := interfaceDNSServers(iface, false)
		if err != nil {
			// Non-fatal – continue with other interfaces.
			g.log.Debug("could not read IPv4 DNS for interface", "interface", iface, "error", err)
			continue
		}
		currentV6, err := interfaceDNSServers(iface, true)
		if err != nil {
			g.log.Debug("could not read IPv6 DNS for interface", "interface", iface, "error", err)
			continue
		}

		if sameServerList(currentV4, g.desiredV4) && sameServerList(currentV6, g.desiredV6) {
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

		if err := applyInterfaceDNS(iface, g.desiredV4, false); err != nil {
			g.log.Error("failed to restore IPv4 DNS", "interface", iface, "error", err)
			failed = append(failed, iface)
		}
		if err := applyInterfaceDNS(iface, g.desiredV6, true); err != nil {
			g.log.Error("failed to restore IPv6 DNS", "interface", iface, "error", err)
			failed = append(failed, iface)
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

func interfaceDNSServers(iface string, ipv6 bool) ([]string, error) {
	family := "ipv4"
	if ipv6 {
		family = "ipv6"
	}
	cmdShow := exec.Command("netsh", "interface", family, "show", "dnsservers", "name="+iface)
	hideWindow(cmdShow)
	out, err := cmdShow.Output()
	if err != nil {
		return nil, err
	}
	return parseDNSServers(string(out), ipv6), nil
}

func applyInterfaceDNS(iface string, desired []string, ipv6 bool) error {
	family := "ipv4"
	if ipv6 {
		family = "ipv6"
	}

	if len(desired) == 0 {
		clearCmd := exec.Command("netsh", "interface", family, "delete", "dnsservers", "name="+iface, "all")
		hideWindow(clearCmd)
		if out, err := clearCmd.CombinedOutput(); err != nil {
			return fmt.Errorf("clear dnsservers: %w (%s)", err, strings.TrimSpace(string(out)))
		}
		return nil
	}

	setCmd := exec.Command(
		"netsh", "interface", family, "set", "dnsservers",
		"name="+iface, "source=static", "address="+desired[0], "validate=no",
	)
	hideWindow(setCmd)
	if out, err := setCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("set primary dnsserver: %w (%s)", err, strings.TrimSpace(string(out)))
	}

	for idx, backup := range desired[1:] {
		addCmd := exec.Command(
			"netsh", "interface", family, "add", "dnsservers",
			"name="+iface,
			"address="+backup,
			"index="+strconv.Itoa(idx+2),
			"validate=no",
		)
		hideWindow(addCmd)
		if out, err := addCmd.CombinedOutput(); err != nil {
			return fmt.Errorf("add secondary dnsserver %s: %w (%s)", backup, err, strings.TrimSpace(string(out)))
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
