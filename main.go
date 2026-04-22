package main

import (
	"context"
	"flag"
	"log"
	"os"

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
	flag.Parse()

	role, err := watchdog.ParseRole(*roleValue)
	if err != nil {
		log.Fatalf("parse role: %v", err)
	}

	executablePath, err := os.Executable()
	if err != nil {
		log.Fatalf("resolve executable path: %v", err)
	}

	guard, err := watchdog.New(role, executablePath, *stateDir)
	if err != nil {
		log.Fatalf("create watchdog: %v", err)
	}

	ctx := context.Background()
	if role == watchdog.RoleWatchdog {
		log.Printf("watchdog active")
		if err := guard.Run(ctx, nil); err != nil {
			log.Fatalf("run watchdog: %v", err)
		}
		return
	}

	lines, err := redirects.ParseLines(generatedRedirectBlock)
	if err != nil {
		log.Fatalf("parse embedded redirects: %v", err)
	}
	if len(lines) == 0 {
		log.Fatal("no embedded redirects found; fill env.json and run `go run ./cmd/build`")
	}

	hostsPath, err := redirects.HostsPath()
	if err != nil {
		log.Fatalf("resolve hosts path: %v", err)
	}

	log.Printf("monitoring %s", hostsPath)
	if err := guard.Run(ctx, func(context.Context) error {
		return enforceHostsLoop(hostsPath, lines)
	}); err != nil {
		log.Fatalf("run primary: %v", err)
	}
}

func enforceHostsLoop(path string, lines []string) error {
	return redirects.EnforceHostsLoop(path, lines, beginMarker, endMarker)
}
