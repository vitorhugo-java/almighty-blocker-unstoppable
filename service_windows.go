//go:build windows

// service_windows.go contains Windows-only service helpers.
//
// The main service lifecycle (start / stop / install) is now handled by
// service_runner.go via github.com/kardianos/service, which internally uses
// the Windows Service Control Manager protocol.
//
// This file is kept for future Windows-specific extensions.
package main

