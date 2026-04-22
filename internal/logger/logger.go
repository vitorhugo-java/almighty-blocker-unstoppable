// Package logger provides structured logging with privacy-preserving domain masking.
//
// Java analogy: think of this as a thin wrapper around java.util.logging.Logger or SLF4J
// that automatically masks sensitive data before writing to the log sink.
package logger

import (
	"log/slog"
	"strings"
)

// MaskDomain replaces the most-specific label of a DNS name with asterisks so that
// individual user queries are not exposed in plain text in log files.
//
// Java analogy: a static utility method like SecurityUtils.maskDomain(String domain).
//
// Examples:
//
//	"www.example.com."  →  "w*w.example.com"
//	"example.com."      →  "e*****e.com"
//	"a.b."              →  "*.b"
func MaskDomain(domain string) string {
	// DNS names often carry a trailing dot (the "root" label); strip it for display.
	domain = strings.TrimSuffix(domain, ".")

	parts := strings.Split(domain, ".")
	if len(parts) == 0 || domain == "" {
		return "[hidden]"
	}

	first := parts[0]
	switch {
	case len(first) == 0:
		parts[0] = "*"
	case len(first) <= 2:
		// Very short labels – mask entirely to avoid fingerprinting.
		parts[0] = strings.Repeat("*", len(first))
	default:
		// Keep first and last character; mask everything in between.
		parts[0] = string(first[0]) + strings.Repeat("*", len(first)-2) + string(first[len(first)-1])
	}

	return strings.Join(parts, ".")
}

// New returns a *slog.Logger tagged with a "component" attribute.
//
// Java analogy: LoggerFactory.getLogger(componentName) in SLF4J.
// Go 1.21+ ships log/slog in the standard library – no third-party library needed.
func New(component string) *slog.Logger {
	// slog.Default() gives the process-wide default logger configured by the
	// application (or the built-in text handler if nothing was configured).
	return slog.Default().With("component", component)
}
