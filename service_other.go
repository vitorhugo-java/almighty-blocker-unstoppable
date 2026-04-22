//go:build !windows

// service_other.go contains non-Windows service stubs.
//
// The main service lifecycle is now handled by service_runner.go via
// github.com/kardianos/service, which natively supports Linux systemd,
// Upstart, and SysV init.
//
// This file is kept for future non-Windows-specific extensions.
package main

