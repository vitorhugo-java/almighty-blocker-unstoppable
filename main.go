package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"almighty-blocker-unstoppable/internal/redirects"
	"almighty-blocker-unstoppable/internal/watchdog"
)

const (
	beginMarker = "# >>> almighty-blocker-unstoppable >>>"
	endMarker   = "# <<< almighty-blocker-unstoppable <<<"
)

func main() {
	roleValue := flag.String("role", string(watchdog.RolePrimary), "process role: primary or watchdog")
	stateDir := flag.String("state-dir", "", "directory used for watchdog heartbeats")
	serviceName := flag.String("service-name", "almighty-blocker", "windows service name")
	flag.Parse()

	isService, err := runningAsWindowsService()
	if err != nil {
		log.Fatalf("detect windows service context: %v", err)
	}
	if isService {
		if err := runWindowsService(*serviceName, *stateDir); err != nil {
			log.Fatalf("run windows service: %v", err)
		}
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := runApplication(ctx, *roleValue, *stateDir, *serviceName); err != nil {
		log.Fatalf("run application: %v", err)
	}
}

func runApplication(ctx context.Context, roleValue string, stateDir string, serviceName string) error {
	role, err := watchdog.ParseRole(roleValue)
	if err != nil {
		return err
	}

	executablePath, err := os.Executable()
	if err != nil {
		return err
	}

	guard, err := watchdog.New(role, executablePath, stateDir)
	if err != nil {
		return err
	}

	if role == watchdog.RoleWatchdog {
		log.Printf("watchdog active")
		if err := guard.Run(ctx, nil); err != nil {
			return err
		}
		return nil
	}

	if err := ensureStartupRegistration(serviceName, executablePath, guard.StateDir); err != nil {
		log.Printf("startup registration check warning: %v", err)
	}

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

	log.Printf("monitoring %s", hostsPath)
	if err := guard.Run(ctx, func(context.Context) error {
		return enforceHostsLoop(ctx, hostsPath, lines)
	}); err != nil {
		return err
	}

	return nil
}

func enforceHostsLoop(ctx context.Context, path string, lines []string) error {
	return redirects.EnforceHostsLoop(ctx, path, lines, beginMarker, endMarker)
}
