// Package main is the entry point for the almighty-blocker-unstoppable service.
//
// Architecture overview (for Java developers):
//   - This is analogous to a Spring Boot application with multiple @Service beans:
//     • config.Loader     → @ConfigurationProperties + @RefreshScope
//     • dnshijack.Guard   → a @Scheduled DNS enforcement bean
//     • firewallguard.Guard → a @Scheduled firewall enforcement bean
//     • camouflage        → a @PostConstruct utility
//     • watchdog.Watchdog → a ScheduledExecutorService that monitors a partner process
//   - main() wires everything together, like a Spring ApplicationContext.
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"almighty-blocker-unstoppable/internal/camouflage"
	"almighty-blocker-unstoppable/internal/config"
	"almighty-blocker-unstoppable/internal/dnshijack"
	"almighty-blocker-unstoppable/internal/firewallguard"
	"almighty-blocker-unstoppable/internal/watchdog"
)

// defaultDNS is used when env.json does not specify DNS entries.
var defaultDNS = []string{"1.1.1.1", "1.0.0.1"}

// main is the application entry point.
//
// Java analogy: public static void main(String[] args) + @SpringBootApplication.
// Flag parsing in Go uses the standard "flag" package instead of annotations.
func main() {
	// --role distinguishes the primary process from the watchdog process that it
	// spawns.  Normal users never set this flag directly.
	roleValue := flag.String("role", string(watchdog.RolePrimary),
		"process role: primary or watchdog")

	// --state-dir is the directory where heartbeat JSON files are exchanged
	// between the primary and watchdog processes.
	stateDir := flag.String("state-dir", "",
		"directory used for watchdog heartbeats (defaults to OS temp dir)")

	// --service-name is the identifier used when registering with the OS service
	// manager (sc.exe on Windows, systemd on Linux).
	serviceName := flag.String("service-name", "almighty-blocker",
		"OS service name / identifier")

	// flag.Parse() reads os.Args[1:] and fills the flag variables.
	// Java analogy: new CommandLineParser().parse(args) in Apache Commons CLI.
	flag.Parse()

	// runAsService handles both cases:
	//   • Running as a managed service (Windows SCM / systemd) → speaks the
	//     native service protocol via kardianos/service.
	//   • Running interactively (terminal / direct invocation) → installs signal
	//     handlers and runs until SIGINT/SIGTERM.
	//
	// This single call replaces the old runningAsWindowsService() + runWindowsService()
	// pattern that required platform-specific stub files.
	if err := runAsService(*roleValue, *serviceName, *stateDir); err != nil {
		log.Fatalf("service: %v", err)
	}
}

// newRootContext returns a context that is cancelled when the process receives
// SIGINT or SIGTERM.  Used by service_runner.go to create the application context.
//
// Java analogy: registering a Runtime.addShutdownHook() that sets a CountDownLatch.
func newRootContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

// runApplication contains the core business logic.  It is called from the
// service runner (service_runner.go) in a goroutine after Start() is invoked.
//
// Parameters:
//   - ctx         : cancelled when the service is asked to stop
//   - roleValue   : "primary" or "watchdog" (see watchdog package)
//   - stateDir    : directory for heartbeat files shared with the watchdog
//   - serviceName : OS service identifier (used for camouflage on Windows)
//
// Java analogy: a @Service class whose run() method is called by ApplicationRunner,
// injected with the parsed config and all dependent beans.
func runApplication(ctx context.Context, roleValue string, stateDir string, serviceName string) error {
	// activeProtection is driven solely by the build tag (protection.go /
	// protection_noprotection.go).  There is no runtime kill-switch; to disable
	// self-defence features rebuild with -tags noprotection.
	// Java analogy: @ConditionalOnProperty("protection.enabled", havingValue="true")
	activeProtection := protectionEnabled

	// ── Runtime configuration (env.json) ─────────────────────────────────────
	// Runtime configuration is embedded into the binary at build time.
	dnsServers := defaultDNS
	blockAddress := []string(nil)
	torEntryIPs := []string(nil)
	if cfg, cfgErr := config.LoadFromBytes([]byte(generatedEnvJSON)); cfgErr != nil {
		log.Printf("warning: could not load embedded env configuration (%v) - using default DNS %v", cfgErr, dnsServers)
	} else {
		if values := cfg.DNS; len(values) > 0 {
			dnsServers = values
		}
		blockAddress = cfg.BlockAddress
		torEntryIPs = cfg.TorEntryIPs
	}

	// Always try to apply DNS/firewall baseline once at startup.
	// In no-protection builds we still apply once, then switch to warn-only monitor mode.
	dnsApply := dnshijack.New(dnsServers, false)
	if err := dnsApply.EnforceOnce(); err != nil {
		log.Printf("warning: initial DNS configuration failed: %v", err)
	}
	fwApply := firewallguard.New(torEntryIPs, blockAddress, dnsServers, false)
	fwApply.RunOnce()

	warnOnly := !activeProtection
	dnsGuard := dnshijack.New(dnsServers, warnOnly)
	fwGuard := firewallguard.New(torEntryIPs, blockAddress, dnsServers, warnOnly)

	// ── Self-defence features (skipped when built with -tags noprotection) ────
	if activeProtection {
		// Camouflage: rename the process / service display name so it blends in
		// with legitimate system processes.
		// On Linux  → prctl(PR_SET_NAME)
		// On Windows → updates registry DisplayName / Description
		camouflage.Randomize(serviceName)

		// In protected builds we continuously re-apply DNS/firewall configuration.
		go dnsGuard.Run(ctx)
		go fwGuard.Run(ctx)
	}

	// ── DNS-only runtime ───────────────────────────────────────────────────────
	// Hosts-file access is intentionally disabled in all builds.
	if !activeProtection {
		// In non-protection builds we set once and only warn if modified.
		go dnsGuard.Run(ctx)
		go fwGuard.Run(ctx)
		log.Printf("running with external DNS+firewall monitor mode (protection disabled at build time)")
		<-ctx.Done()
		return nil
	}

	// With protection enabled, parse the role and start the watchdog system.
	role, err := watchdog.ParseRole(roleValue)
	if err != nil {
		return err
	}

	// os.Executable() returns the path to the running binary.
	// Java analogy: ProcessHandle.current().info().command().
	executablePath, err := os.Executable()
	if err != nil {
		return err
	}

	// watchdog.New builds a Watchdog instance for the given role.
	// Each instance knows about its "partner" (primary↔watchdog) and spawns it
	// if the heartbeat goes stale.
	wdg, err := watchdog.New(role, executablePath, stateDir)
	if err != nil {
		return err
	}

	// The watchdog role only runs the heartbeat loop; no workload.
	if role == watchdog.RoleWatchdog {
		log.Printf("watchdog active")
		return wdg.Run(ctx, nil)
	}

	// The primary role ensures startup registration and then runs without any
	// hosts-file workload. The watchdog still supervises process liveness.
	if err := ensureStartupRegistration(serviceName, executablePath, wdg.StateDir); err != nil {
		log.Printf("startup registration check warning: %v", err)
	}

	log.Printf("running with watchdog supervision (hosts access disabled)")
	return wdg.Run(ctx, nil)
}
