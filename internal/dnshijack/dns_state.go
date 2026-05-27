package dnshijack

import (
	"net"
	"strings"
)

func splitDesiredServers(desired []string) ([]string, []string) {
	v4 := make([]string, 0, len(desired))
	v6 := make([]string, 0, len(desired))
	seenV4 := map[string]struct{}{}
	seenV6 := map[string]struct{}{}

	for _, server := range desired {
		candidate := strings.TrimSpace(server)
		if candidate == "" {
			continue
		}
		if host, _, err := net.SplitHostPort(candidate); err == nil {
			candidate = host
		}
		candidate = strings.Trim(candidate, "[]")
		ip := net.ParseIP(candidate)
		if ip == nil {
			continue
		}

		normalized := ip.String()
		if ip.To4() != nil {
			if _, exists := seenV4[normalized]; exists {
				continue
			}
			seenV4[normalized] = struct{}{}
			v4 = append(v4, normalized)
			continue
		}

		if _, exists := seenV6[normalized]; exists {
			continue
		}
		seenV6[normalized] = struct{}{}
		v6 = append(v6, normalized)
	}

	return v4, v6
}

func parseDNSServers(output string, wantIPv6 bool) []string {
	servers := make([]string, 0, 4)
	seen := map[string]struct{}{}

	for _, token := range strings.Fields(output) {
		candidate := strings.Trim(token, "[](){}<>,;\"'")
		if idx := strings.Index(candidate, "%"); idx >= 0 {
			candidate = candidate[:idx]
		}
		ip := net.ParseIP(candidate)
		if ip == nil {
			continue
		}
		isIPv6 := ip.To4() == nil
		if isIPv6 != wantIPv6 {
			continue
		}

		normalized := ip.String()
		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		servers = append(servers, normalized)
	}

	return servers
}

func sameServerList(current []string, desired []string) bool {
	if len(current) != len(desired) {
		return false
	}
	for i := range current {
		if current[i] != desired[i] {
			return false
		}
	}
	return true
}
