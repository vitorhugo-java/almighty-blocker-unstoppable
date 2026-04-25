package firewallguard

import (
	"context"
	"net"
	"sort"
	"strings"
	"time"
)

func parseBlockAddress(values []string) (domains []string, ips []string) {
	for _, raw := range values {
		item := strings.TrimSpace(raw)
		if item == "" {
			continue
		}

		candidate := strings.Trim(item, "[]")
		if ip := net.ParseIP(candidate); ip != nil {
			ips = append(ips, ip.String())
			continue
		}

		domains = append(domains, strings.TrimSuffix(strings.ToLower(item), "."))
	}

	return domains, dedupeSorted(ips)
}

func mergeIPs(inputs ...[]string) []string {
	merged := make([]string, 0)
	for _, in := range inputs {
		for _, item := range in {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			ip := net.ParseIP(strings.Trim(item, "[]"))
			if ip == nil {
				continue
			}
			merged = append(merged, ip.String())
		}
	}
	return dedupeSorted(merged)
}

func resolveDomains(domains []string, dnsServers []string) []string {
	if len(domains) == 0 {
		return nil
	}

	resolver := newResolver(dnsServers)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	out := make([]string, 0, len(domains)*2)
	for _, domain := range domains {
		domain = strings.TrimSpace(domain)
		if domain == "" {
			continue
		}
		ips, err := resolver.LookupIPAddr(ctx, domain)
		if err != nil {
			continue
		}
		for _, ip := range ips {
			out = append(out, ip.IP.String())
		}
	}

	return dedupeSorted(out)
}

func newResolver(dnsServers []string) *net.Resolver {
	if len(dnsServers) == 0 {
		return net.DefaultResolver
	}

	server := strings.TrimSpace(dnsServers[0])
	if server == "" {
		return net.DefaultResolver
	}

	if host, port, err := net.SplitHostPort(server); err == nil {
		if host != "" && port != "" {
			server = net.JoinHostPort(host, port)
		}
	} else {
		server = net.JoinHostPort(server, "53")
	}

	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := &net.Dialer{Timeout: 3 * time.Second}
			return d.DialContext(ctx, "udp", server)
		},
	}
}

func dedupeSorted(in []string) []string {
	if len(in) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, item := range in {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}

	sort.Strings(out)
	return out
}

func splitChunks(in []string, size int) [][]string {
	if len(in) == 0 || size <= 0 {
		return nil
	}
	chunks := make([][]string, 0, (len(in)+size-1)/size)
	for i := 0; i < len(in); i += size {
		end := i + size
		if end > len(in) {
			end = len(in)
		}
		chunks = append(chunks, in[i:end])
	}
	return chunks
}
