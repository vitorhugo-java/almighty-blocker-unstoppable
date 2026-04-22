// Package main is the entry point for the almighty-blocker-unstoppable service.
//
// Architecture overview (for Java developers):
//   - This is analogous to a Spring Boot application with multiple @Service beans:
//     • config.Loader     → @ConfigurationProperties + @RefreshScope
//     • dnsengine.Server  → a Netty-based UDP server bean
//     • dnshijack.Guard   → a @Scheduled task bean
//     • camouflage        → a @PostConstruct utility
//     • watchdog.Watchdog → a ScheduledExecutorService that monitors a partner process
//   - main() wires everything together, like a Spring ApplicationContext.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"almighty-blocker-unstoppable/internal/camouflage"
	"almighty-blocker-unstoppable/internal/config"
	"almighty-blocker-unstoppable/internal/dnshijack"
	"almighty-blocker-unstoppable/internal/dnsengine"
	"almighty-blocker-unstoppable/internal/redirects"
	"almighty-blocker-unstoppable/internal/watchdog"
)

const (
	beginMarker = "# >>> almighty-blocker-unstoppable >>>"
	endMarker   = "# <<< almighty-blocker-unstoppable <<<"
)

// defaultUpstreams is used when env.json does not specify upstreamDNS entries.
// These are the well-known public DNS resolvers from Google and Cloudflare.
var defaultUpstreams = []string{"8.8.8.8:53", "1.1.1.1:53"}

// main is the application entry point.
//
// Java analogy: public static void main(String[] args) + @SpringBootApplication.
// Flag parsing in Go uses the standard "flag" package instead of annotations.
func main() {
	// --protection controls whether the self-defence features are active at runtime.
	// Values: "on" (default) or "off".
	// When "off": camouflage is skipped, DNS hijack protection is disabled, and
	// the watchdog is not started – the service can be stopped gracefully.
	//
	// Note: this is the RUNTIME kill-switch.  A build-time kill-switch also exists
	// via the "noprotection" build tag (see protection.go / protection_noprotection.go).
	protection := flag.String("protection", "on",
		`protection mode: "on" (default) enables all self-defence features; `+
			`"off" disables camouflage, DNS hijack guard, and the watchdog`)

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

	protectionOff := *protection == "off"

	// runAsService handles both cases:
	//   • Running as a managed service (Windows SCM / systemd) → speaks the
	//     native service protocol via kardianos/service.
	//   • Running interactively (terminal / direct invocation) → installs signal
	//     handlers and runs until SIGINT/SIGTERM.
	//
	// This single call replaces the old runningAsWindowsService() + runWindowsService()
	// pattern that required platform-specific stub files.
	if err := runAsService(*roleValue, *serviceName, *stateDir, protectionOff); err != nil {
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
//   - ctx          : cancelled when the service is asked to stop
//   - roleValue    : "primary" or "watchdog" (see watchdog package)
//   - stateDir     : directory for heartbeat files shared with the watchdog
//   - serviceName  : OS service identifier (used for camouflage on Windows)
//   - protectionOff: true when --protection off was passed at startup
//
// Java analogy: a @Service class whose run() method is called by ApplicationRunner,
// injected with the parsed config and all dependent beans.
func runApplication(ctx context.Context, roleValue string, stateDir string, serviceName string, protectionOff bool) error {
	// activeProtection = build-tag value AND runtime flag combined.
	// Both must be "on" for self-defence features to activate.
	// Java analogy: @ConditionalOnProperty("protection.enabled", havingValue="true")
	activeProtection := protectionEnabled && !protectionOff

	// ── Embedded block-list (compiled in at build time) ──────────────────────
	// generatedRedirectBlock is a Go string constant generated by cmd/build.
	// ParseLines normalises each entry into "0.0.0.0 hostname" format.
	lines, err := redirects.ParseLines(generatedRedirectBlock)
	if err != nil {
		return err
	}
	if len(lines) == 0 {
		return fmt.Errorf("no embedded redirects found; fill env.json and run go run ./cmd/build")
	}

	hostsPath, err := redirects.HostsPath()
	if err != nil {
		return err
	}

	// ── Runtime configuration (env.json) ─────────────────────────────────────
	// config.NewLoader reads env.json synchronously; if the file is absent or
	// malformed we fall back to sensible defaults and log a warning.
	upstreams := defaultUpstreams
	var cfgLoader *config.Loader
	if cl, cfgErr := config.NewLoader("env.json"); cfgErr != nil {
		log.Printf("warning: could not load env.json (%v) – using default upstream DNS %v", cfgErr, upstreams)
	} else {
		cfgLoader = cl
		if us := cfgLoader.Config().UpstreamDNS; len(us) > 0 {
			upstreams = us
		}
	}

	// ── DNS engine ────────────────────────────────────────────────────────────
	// Start a local DNS server on 127.0.0.1:53 that forwards queries upstream.
	// Goroutines in Go are very lightweight (~2 KB) – think of them as virtual
	// threads (Project Loom) rather than OS threads.
	dnsServer := dnsengine.New("127.0.0.1:53", upstreams)
	go func() {
		if err := dnsServer.Run(ctx); err != nil {
			log.Printf("DNS server stopped: %v", err)
		}
	}()

	// ── Hot-reload watcher ────────────────────────────────────────────────────
	// Watch env.json via fsnotify and push updated upstream lists to the DNS
	// server without restarting the process.
	if cfgLoader != nil {
		go func() {
			if err := cfgLoader.Watch(ctx, func(c config.EnvConfig) {
				if len(c.UpstreamDNS) > 0 {
					dnsServer.UpdateUpstreams(c.UpstreamDNS)
				}
			}); err != nil {
				log.Printf("config watcher stopped: %v", err)
			}
		}()
	}

	// ── Self-defence features (skipped when --protection off) ─────────────────
	if activeProtection {
		// Camouflage: rename the process / service display name so it blends in
		// with legitimate system processes.
		// On Linux  → prctl(PR_SET_NAME)
		// On Windows → updates registry DisplayName / Description
		camouflage.Randomize(serviceName)

		// DNS hijack guard: every 10 s verify the system DNS still points to
		// 127.0.0.1 and forcibly restore it if not.
		dnsGuard := dnshijack.New()
		go dnsGuard.Run(ctx)
	}

	// ── Hosts-file enforcement + watchdog ─────────────────────────────────────
	// When protection is disabled we run a simple single-process loop.
	if !activeProtection {
		log.Printf("monitoring %s (protection disabled)", hostsPath)
		return enforceHostsLoop(ctx, hostsPath, lines)
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

	// The primary role ensures startup registration and then runs the hosts loop
	// inside the watchdog envelope so the watchdog can restart it if it crashes.
	if err := ensureStartupRegistration(serviceName, executablePath, wdg.StateDir); err != nil {
		log.Printf("startup registration check warning: %v", err)
	}

	log.Printf("monitoring %s", hostsPath)
	return wdg.Run(ctx, func(context.Context) error {
		return enforceHostsLoop(ctx, hostsPath, lines)
	})
}

// enforceHostsLoop delegates to the redirects package loop, injecting the
// managed-block markers defined in this package.
func enforceHostsLoop(ctx context.Context, path string, lines []string) error {
	return redirects.EnforceHostsLoop(ctx, path, lines, beginMarker, endMarker)
}
