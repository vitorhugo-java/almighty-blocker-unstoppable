//go:build linux

// Package dnshijack provides DNS configuration protection.
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
// Overwriting it with configured nameserver values keeps system DNS pinned.
const resolvConf = "/etc/resolv.conf"

// checkInterval is how often we inspect the DNS configuration.
// The problem specification mandates 10 seconds.
const checkInterval = 10 * time.Second

// Guard periodically verifies that the system DNS resolver points to the
// configured external DNS entries
// and restores it if another process (or user) changes it.
//
// Java analogy: a ScheduledExecutorService task that runs every 10 seconds,
// reads a file, and writes it back when the content has drifted.
type Guard struct {
	log      *slog.Logger
	desired  []string
	warnOnly bool
	mismatch bool
}

// New creates a new Guard instance.
func New(desired []string, warnOnly bool) *Guard {
	servers := normalizeDNSServerList(desired)
	if len(servers) == 0 {
		servers = []string{"1.1.1.1", "1.0.0.1"}
	}
	return &Guard{log: logger.New("dns-hijack-guard"), desired: servers, warnOnly: warnOnly}
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

// EnforceOnce applies configured DNS values immediately.
func (g *Guard) EnforceOnce() error {
	return g.enforce()
}

// enforce checks /etc/resolv.conf and overwrites it when the active nameserver
// list no longer matches the desired DNS values. The write is performed
// atomically via write-to-temp + rename so that concurrent readers never see a
// partially written file.
func (g *Guard) enforce() error {
	current, err := os.ReadFile(resolvConf)
	if err != nil {
		return err
	}

	currentServers := parseResolvNameservers(current)
	if sameServerList(currentServers, g.desired) {
		if g.mismatch {
			g.log.Info("DNS restored", "path", resolvConf)
			g.mismatch = false
		}
		return nil // Already correct – nothing to do.
	}

	if !g.mismatch {
		g.log.Warn("DNS change detected in " + resolvConf)
		g.mismatch = true
	}
	if g.warnOnly {
		return nil
	}

	// Resolve symlinks: on many Linux distributions /etc/resolv.conf is a
	// symlink managed by systemd-resolved or NetworkManager.  Replacing the
	// path directly (os.Rename → target) would unlink the symlink and leave
	// a regular file, permanently breaking that management layer.  Instead,
	// resolve to the real file and write there so the symlink is preserved.
	writeTarget := resolvConf
	if resolved, err := filepath.EvalSymlinks(resolvConf); err == nil {
		writeTarget = resolved
	}

	expectedContent := buildResolvContent(g.desired)

	// Write atomically: create a temp file in the same directory, then rename.
	// rename(2) is atomic on POSIX systems – readers always see either the old
	// or the new file, never a partial write.
	// Java analogy: Files.move(tmp, target, ATOMIC_MOVE, REPLACE_EXISTING).
	dir := filepath.Dir(writeTarget)
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

	// Atomic rename – replaces the real resolv.conf target in a single syscall.
	if err := os.Rename(tmpName, writeTarget); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("rename temp resolv.conf: %w", err)
	}

	g.mismatch = false

	return nil
}

func buildResolvContent(servers []string) string {
	if len(servers) == 0 {
		return "nameserver 1.1.1.1\n"
	}
	lines := make([]string, 0, len(servers))
	for _, server := range servers {
		lines = append(lines, "nameserver "+server)
	}
	return strings.Join(lines, "\n") + "\n"
}
