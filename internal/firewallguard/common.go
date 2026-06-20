package firewallguard

import (
	"net"
	"sort"
	"strings"
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

// staleChunkIndexes returns 1-based chunk indexes that should be deleted when
// the previous chunk count is larger than the current chunk count.
func staleChunkIndexes(previous int, current int) []int {
	if previous <= current {
		return nil
	}
	out := make([]int, 0, previous-current)
	for i := current + 1; i <= previous; i++ {
		out = append(out, i)
	}
	return out
}
