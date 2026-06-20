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

	"golang.org/x/sys/windows/registry"

	"almighty-blocker-unstoppable/internal/logger"
)

// checkInterval is how often we inspect the DNS configuration.
const checkInterval = 10 * time.Second

// dohTemplate is the Cloudflare family (malware + adult) DNS-over-HTTPS endpoint.
// Every configured DNS server IP is mapped to this template so Windows resolves
// over encrypted HTTPS instead of hijackable plaintext UDP/TCP on port 53.
const dohTemplate = "https://family.cloudflare-dns.com/dns-query"

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
	// lastSeen maps an interface name to the signature of the last drifted DNS
	// state we logged for it. Tracking the value (instead of a bool) lets us
	// re-log every distinct change, which matters in warn-only/no-protection
	// builds where we never remediate and reset the state.
	lastSeen map[string]string
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
		lastSeen:  map[string]string{},
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

	// Register the encrypted (DoH) endpoint for every desired server IP before
	// applying them, so Windows auto-upgrades the adapters to DNS-over-HTTPS.
	g.ensureDoHEncryption(append(append([]string{}, g.desiredV4...), g.desiredV6...))

	// Resolve adapter friendly-name → interface GUID so we can read/write the
	// per-adapter DoH registry settings below.
	guidByName := interfaceGUIDs()

	var failed []string

	for _, iface := range ifaces {
		currentV4, errV4 := interfaceDNSServers(iface, false)
		if errV4 != nil {
			g.log.Debug("could not read IPv4 DNS for interface", "interface", iface, "error", errV4)
		}
		currentV6, errV6 := interfaceDNSServers(iface, true)
		if errV6 != nil {
			g.log.Debug("could not read IPv6 DNS for interface", "interface", iface, "error", errV6)
		}
		// Only skip remediation when both families are confirmed in the desired
		// state. If any read fails, we treat it as potential drift and reapply.
		readOK := errV4 == nil && errV6 == nil
		dnsOK := readOK && sameServerList(currentV4, g.desiredV4) && sameServerList(currentV6, g.desiredV6)

		// Per-adapter DoH is what actually upgrades resolution to HTTPS. The
		// global encryption mapping (ensureDoHEncryption) only advertises that
		// the server supports DoH; without the per-interface DohFlags the client
		// keeps resolving over plaintext UDP/TCP.
		guid := guidByName[strings.ToLower(iface)]
		dohMissing := guid != "" && g.interfaceDoHMissing(guid)

		if dnsOK && !dohMissing {
			if _, drifted := g.lastSeen[iface]; drifted {
				g.log.Info("DNS restored", "interface", iface)
				delete(g.lastSeen, iface)
			}
			continue
		}

		if !dnsOK {
			// Re-log on every distinct drift value, not just the first transition.
			sig := strings.Join(append(append([]string{}, currentV4...), currentV6...), ",")
			if g.lastSeen[iface] != sig {
				g.log.Warn("DNS change detected", "interface", iface, "servers", sig)
				g.lastSeen[iface] = sig
			}
		} else if dohMissing {
			g.log.Warn("DoH not active on interface", "interface", iface)
		}

		if g.warnOnly {
			continue
		}

		// Write the per-adapter DoH registry first, then (re)apply the DNS
		// servers so the DNS client reloads the interface configuration and
		// starts resolving over HTTPS.
		if guid != "" && dohMissing {
			g.applyInterfaceDoH(guid)
		}

		interfaceFailed := false
		if err := applyInterfaceDNS(iface, g.desiredV4, false); err != nil {
			g.log.Error("failed to restore IPv4 DNS", "interface", iface, "error", err)
			interfaceFailed = true
		}
		if err := applyInterfaceDNS(iface, g.desiredV6, true); err != nil {
			g.log.Error("failed to restore IPv6 DNS", "interface", iface, "error", err)
			interfaceFailed = true
		}

		if interfaceFailed {
			failed = append(failed, iface)
		} else {
			delete(g.lastSeen, iface)
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("failed to enforce DNS on interfaces: %s", strings.Join(failed, ", "))
	}
	return nil
}

func interfaceDNSServers(iface string, ipv6 bool) ([]string, error) {
	var commands [][]string
	if ipv6 {
		commands = [][]string{
			{"interface", "ipv6", "show", "dnsservers", "name=" + iface},
			{"interface", "ipv6", "show", "dnsservers", "interface=" + iface},
		}
	} else {
		commands = [][]string{
			{"interface", "ipv4", "show", "dnsservers", "name=" + iface},
			{"interface", "ip", "show", "dns", "name=" + iface},
		}
	}

	out, err := runNetshCommandVariants(commands)
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
		var clearCommands [][]string
		if ipv6 {
			clearCommands = [][]string{
				{"interface", "ipv6", "delete", "dnsservers", "name=" + iface, "all"},
				{"interface", "ipv6", "delete", "dnsservers", "interface=" + iface, "all"},
			}
		} else {
			clearCommands = [][]string{
				{"interface", "ipv4", "delete", "dnsservers", "name=" + iface, "all"},
				{"interface", "ip", "set", "dns", "name=" + iface, "source=dhcp"},
			}
		}
		if _, err := runNetshCommandVariants(clearCommands); err != nil {
			return fmt.Errorf("clear dnsservers: %w", err)
		}
		return nil
	}

	var setCommands [][]string
	if ipv6 {
		setCommands = [][]string{
			{"interface", family, "set", "dnsservers", "name=" + iface, "source=static", "address=" + desired[0], "validate=no"},
			{"interface", family, "set", "dnsservers", "interface=" + iface, "source=static", "address=" + desired[0], "validate=no"},
		}
	} else {
		setCommands = [][]string{
			{"interface", family, "set", "dnsservers", "name=" + iface, "source=static", "address=" + desired[0], "validate=no"},
			{"interface", "ip", "set", "dns", "name=" + iface, "static", desired[0], "primary"},
		}
	}
	if _, err := runNetshCommandVariants(setCommands); err != nil {
		return fmt.Errorf("set primary dnsserver: %w", err)
	}

	for idx, backup := range desired[1:] {
		index := strconv.Itoa(idx + 2)
		var addCommands [][]string
		if ipv6 {
			addCommands = [][]string{
				{"interface", family, "add", "dnsservers", "name=" + iface, "address=" + backup, "index=" + index, "validate=no"},
				{"interface", family, "add", "dnsservers", "interface=" + iface, "address=" + backup, "index=" + index, "validate=no"},
			}
		} else {
			addCommands = [][]string{
				{"interface", family, "add", "dnsservers", "name=" + iface, "address=" + backup, "index=" + index, "validate=no"},
				{"interface", "ip", "add", "dns", "name=" + iface, "addr=" + backup, "index=" + index},
			}
		}
		if _, err := runNetshCommandVariants(addCommands); err != nil {
			return fmt.Errorf("add secondary dnsserver %s: %w", backup, err)
		}
	}

	return nil
}

func runNetshCommandVariants(variants [][]string) ([]byte, error) {
	// Different Windows versions and adapter stacks accept slightly different
	// netsh forms (e.g. ipv4 vs legacy ip context, name= vs interface=). Try
	// variants in order and stop at the first successful command.
	var lastErr error
	for _, args := range variants {
		cmd := exec.Command("netsh", args...)
		hideWindow(cmd)
		out, err := cmd.CombinedOutput()
		if err == nil {
			return out, nil
		}
		lastErr = fmt.Errorf("%w (%s)", err, strings.TrimSpace(string(out)))
	}
	if lastErr == nil {
		return nil, fmt.Errorf("no netsh command variant provided")
	}
	return nil, lastErr
}

// ensureDoHEncryption maps each desired DNS server IP to the Cloudflare family
// DoH template with strict, fallback-free auto-upgrade. These mappings are
// global (keyed by server IP, not per interface), so configuring the IP as an
// adapter's DNS server makes Windows resolve over HTTPS. udpfallback=no ensures
// the resolver never silently downgrades to plaintext (and hijackable) DNS.
func (g *Guard) ensureDoHEncryption(servers []string) {
	for _, server := range servers {
		server = strings.TrimSpace(server)
		if server == "" {
			continue
		}

		// Delete any stale mapping first; "add" fails if one already exists.
		del := exec.Command("netsh", "dns", "delete", "encryption", "server="+server)
		hideWindow(del)
		_ = del.Run()

		add := exec.Command(
			"netsh", "dns", "add", "encryption",
			"server="+server,
			"dohtemplate="+dohTemplate,
			"autoupgrade=yes",
			"udpfallback=no",
		)
		hideWindow(add)
		if out, err := add.CombinedOutput(); err != nil {
			g.log.Error("failed to configure DoH encryption", "server", server, "error", err, "output", strings.TrimSpace(string(out)))
		}
	}
}

// dohEncryptionRequired is the DohFlags value meaning "encrypted only": Windows
// resolves over DoH and never falls back to plaintext DNS. It matches the strict
// udpfallback=no policy registered by ensureDoHEncryption. (DohFlags=1 would
// allow UDP fallback.)
const dohEncryptionRequired = 2

// dohRegPath returns the per-interface DoH registry path for the given adapter
// GUID. IPv4 servers live under "Doh", IPv6 servers under "Doh6".
func dohRegPath(guid string, ipv6 bool) string {
	sub := "Doh"
	if ipv6 {
		sub = "Doh6"
	}
	return `SYSTEM\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters\` + guid + `\DohInterfaceSettings\` + sub
}

// dohFamilies pairs each desired server family with its IPv6 flag.
func (g *Guard) dohFamilies() []struct {
	servers []string
	ipv6    bool
} {
	return []struct {
		servers []string
		ipv6    bool
	}{
		{g.desiredV4, false},
		{g.desiredV6, true},
	}
}

// interfaceDoHMissing reports whether any desired server lacks an "encrypted
// only" DoH entry on the given adapter. It is read-only and is used in both
// enforcing and warn-only modes to detect drift before deciding to remediate.
func (g *Guard) interfaceDoHMissing(guid string) bool {
	for _, fam := range g.dohFamilies() {
		base := dohRegPath(guid, fam.ipv6)
		for _, server := range fam.servers {
			server = strings.TrimSpace(server)
			if server == "" {
				continue
			}
			key, err := registry.OpenKey(registry.LOCAL_MACHINE, base+`\`+server, registry.QUERY_VALUE)
			if err != nil {
				return true
			}
			val, _, err := key.GetIntegerValue("DohFlags")
			key.Close()
			if err != nil || val != dohEncryptionRequired {
				return true
			}
		}
	}
	return false
}

// applyInterfaceDoH writes the per-adapter DoH registry entries (DohFlags =
// encrypted only) for every desired server. The encrypted template itself comes
// from the global auto-upgrade mapping registered by ensureDoHEncryption, so the
// interface key only needs the flag. Requires Administrator/SYSTEM (HKLM write).
func (g *Guard) applyInterfaceDoH(guid string) {
	for _, fam := range g.dohFamilies() {
		base := dohRegPath(guid, fam.ipv6)
		for _, server := range fam.servers {
			server = strings.TrimSpace(server)
			if server == "" {
				continue
			}
			key, _, err := registry.CreateKey(registry.LOCAL_MACHINE, base+`\`+server, registry.SET_VALUE)
			if err != nil {
				g.log.Error("failed to open DoH interface key", "guid", guid, "server", server, "error", err)
				continue
			}
			if err := key.SetQWordValue("DohFlags", dohEncryptionRequired); err != nil {
				g.log.Error("failed to set DohFlags", "guid", guid, "server", server, "error", err)
			}
			key.Close()
		}
	}
}

// interfaceGUIDs maps each network adapter's friendly name (lower-cased) to its
// interface GUID by reading the network class registry key. The GUID is the same
// identifier used under Dnscache\InterfaceSpecificParameters. Best-effort: on any
// read error the (possibly partial) map is returned.
func interfaceGUIDs() map[string]string {
	const netClass = `SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}`

	result := map[string]string{}
	root, err := registry.OpenKey(registry.LOCAL_MACHINE, netClass, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return result
	}
	defer root.Close()

	guids, err := root.ReadSubKeyNames(-1)
	if err != nil {
		return result
	}
	for _, guid := range guids {
		conn, err := registry.OpenKey(registry.LOCAL_MACHINE, netClass+`\`+guid+`\Connection`, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		name, _, err := conn.GetStringValue("Name")
		conn.Close()
		if err != nil || name == "" {
			continue
		}
		result[strings.ToLower(name)] = guid
	}
	return result
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

// createNoWindow (CREATE_NO_WINDOW) keeps every netsh invocation from ever
// allocating a console, so the protected GUI build performs its DNS checks
// without flashing a terminal window.
const createNoWindow = 0x08000000

func hideWindow(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
}
