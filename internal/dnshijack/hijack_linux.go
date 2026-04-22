//go:build linux

// Package dnshijack provides DNS hijack protection.
// On Linux it enforces /etc/resolv.conf every 10 seconds.
//
// Java analogy: a @Scheduled(fixedDelay = 10_000) method inside a Spring @Service
// that checks a system file and repairs it when tampered with.
package dnshijack

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"almighty-blocker-unstoppable/internal/logger"
)

// resolvConf is the path to the Linux DNS resolver configuration.
// Overwriting it with "nameserver 127.0.0.1" redirects all system DNS queries
// to our local DNS server.
const resolvConf = "/etc/resolv.conf"

// checkInterval is how often we inspect the DNS configuration.
// The problem specification mandates 10 seconds.
const checkInterval = 10 * time.Second

// expectedContent is what /etc/resolv.conf must contain.
const expectedContent = "nameserver 127.0.0.1\n"

// Guard periodically verifies that the system DNS resolver points to 127.0.0.1
// and restores it if another process (or user) changes it.
//
// Java analogy: a ScheduledExecutorService task that runs every 10 seconds,
// reads a file, and writes it back when the content has drifted.
type Guard struct {
	log *slog.Logger
}

// New creates a new Guard instance.
func New() *Guard {
	return &Guard{log: logger.New("dns-hijack-guard")}
}

// Run starts the protection loop and blocks until ctx is cancelled.
// Intended to run in its own goroutine.
//
// Java analogy: Runnable passed to ScheduledExecutorService.scheduleWithFixedDelay().
func (g *Guard) Run(ctx context.Context) {
	// Enforce immediately on startup before the first tick fires.
	if err := g.enforce(); err != nil {
		g.log.Error("initial DNS enforcement failed", "error", err)
	}

	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop() // Always stop timers to free OS resources – like cancelling a Java ScheduledFuture.

	for {
		select {
		case <-ctx.Done():
			// Parent context cancelled – stop the loop cleanly.
			return
		case <-ticker.C:
			if err := g.enforce(); err != nil {
				g.log.Error("DNS enforcement failed", "error", err)
			}
		}
	}
}

// enforce checks /etc/resolv.conf and overwrites it if it no longer points to
// 127.0.0.1.  The write is performed atomically via write-to-temp + rename so
// that concurrent readers never see a partially written file.
func (g *Guard) enforce() error {
	current, err := os.ReadFile(resolvConf)
	if err != nil {
		return err
	}

	// Check if the expected nameserver line is present anywhere in the file.
	if strings.Contains(string(current), "nameserver 127.0.0.1") {
		return nil // Already correct – nothing to do.
	}

	g.log.Warn("DNS hijack detected – restoring 127.0.0.1 in " + resolvConf)

	// Write atomically: create a temp file in the same directory, then rename.
	// rename(2) is atomic on POSIX systems – readers always see either the old
	// or the new file, never a partial write.
	// Java analogy: Files.move(tmp, target, ATOMIC_MOVE, REPLACE_EXISTING).
	dir := filepath.Dir(resolvConf)
	tmp, err := os.CreateTemp(dir, ".resolv.conf.tmp")
	if err != nil {
		return fmt.Errorf("create temp resolv.conf: %w", err)
	}
	tmpName := tmp.Name()

	if _, err := tmp.WriteString(expectedContent); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("write temp resolv.conf: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("close temp resolv.conf: %w", err)
	}

	// Ensure the temp file has the correct permissions before renaming.
	if err := os.Chmod(tmpName, 0o644); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("chmod temp resolv.conf: %w", err)
	}

	// Atomic rename – replaces /etc/resolv.conf in a single syscall.
	if err := os.Rename(tmpName, resolvConf); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("rename temp resolv.conf: %w", err)
	}

	return nil
}
