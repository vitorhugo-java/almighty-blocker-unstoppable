package torfetch

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"
)

const DefaultOnionooGuardURL = "https://onionoo.torproject.org/details?flag=Guard&running=true&fields=or_addresses"

const requestTimeout = 30 * time.Second
const estimatedGuardCapacity = 1024

type onionooResponse struct {
	Relays []struct {
		OrAddresses []string `json:"or_addresses"`
	} `json:"relays"`
}

func FetchGuardIPs(ctx context.Context, client *http.Client, endpoint string, limit int) ([]string, error) {
	if client == nil {
		client = &http.Client{Timeout: requestTimeout}
	}
	if strings.TrimSpace(endpoint) == "" {
		endpoint = DefaultOnionooGuardURL
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("unexpected Onionoo status: %s", resp.Status)
	}

	var decoded onionooResponse
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return nil, err
	}

	seen := make(map[string]struct{})
	out := make([]string, 0, estimatedGuardCapacity)
	for _, relay := range decoded.Relays {
		for _, rawAddr := range relay.OrAddresses {
			host := normalizeAddress(rawAddr)
			if host == "" {
				continue
			}
			if _, exists := seen[host]; exists {
				continue
			}
			seen[host] = struct{}{}
			out = append(out, host)
		}
	}

	sort.Strings(out)
	if limit > 0 && len(out) > limit {
		return out[:limit], nil
	}
	return out, nil
}

func RunRefreshLoop(ctx context.Context, client *http.Client, endpoint string, interval time.Duration, limit int, log *slog.Logger, apply func([]string)) {
	if apply == nil {
		return
	}
	if interval <= 0 {
		interval = 6 * time.Hour
	}
	if log == nil {
		log = slog.Default().With("component", "tor-fetch")
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			log.Error("tor refresh loop crashed", "panic", recovered)
		}
	}()

	refresh := func() {
		fetchCtx, cancel := context.WithTimeout(ctx, requestTimeout)
		defer cancel()
		ips, err := FetchGuardIPs(fetchCtx, client, endpoint, limit)
		if err != nil {
			log.Warn("failed to refresh tor guard ips", "error", err)
			return
		}
		log.Info("tor guard ips refreshed", "count", len(ips))
		apply(ips)
	}

	refresh()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			refresh()
		}
	}
}

func normalizeAddress(raw string) string {
	addr := strings.TrimSpace(raw)
	if addr == "" {
		return ""
	}

	host := addr
	if parsedHost, _, splitErr := net.SplitHostPort(addr); splitErr == nil {
		host = parsedHost
	}

	host = strings.Trim(host, "[]")
	ip := net.ParseIP(host)
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}
