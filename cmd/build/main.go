package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"almighty-blocker-unstoppable/internal/redirects"
)

const onionooGuardURL = "https://onionoo.torproject.org/details?flag=Guard&running=true&fields=or_addresses"

type onionooResponse struct {
	Relays []struct {
		OrAddresses []string `json:"or_addresses"`
	} `json:"relays"`
}

func main() {
	configPath := flag.String("config", "env.json", "path to env json")
	outputDir := flag.String("out", "dist", "directory for built binaries")
	binaryName := flag.String("binary", "almighty-blocker", "base name for output binaries")
	targetsValue := flag.String("targets", "windows/amd64,linux/amd64", "comma-separated GOOS/GOARCH targets")
	noProtection := flag.Bool("no-protection", false, "build with watchdog, system start, and system start monitoring disabled")
	refreshTorIPs := flag.Bool("refresh-tor-ips", false, "refresh torEntryIPs in env.json from Onionoo before build")
	torIPLimit := flag.Int("tor-ip-limit", 0, "maximum number of unique IP entries kept in torEntryIPs (0 = unlimited)")
	flag.Parse()

	if err := normalizeConfigTorIPs(*configPath, *refreshTorIPs, *torIPLimit); err != nil {
		exitf("normalize torEntryIPs: %v", err)
	}

	envContent, err := os.ReadFile(*configPath)
	if err != nil {
		exitf("read config for embedding: %v", err)
	}

	generatedEnvSource, err := redirects.GenerateGoSource("main", "generatedEnvJSON", string(envContent))
	if err != nil {
		exitf("generate embedded env source: %v", err)
	}

	if err := os.WriteFile("generated_env.go", generatedEnvSource, 0o644); err != nil {
		exitf("write generated_env.go: %v", err)
	}

	sourceURLs, err := redirects.LoadSources(*configPath)
	if err != nil {
		exitf("load sources: %v", err)
	}

	block := ""
	if len(sourceURLs) > 0 {
		block, err = redirects.FetchBlock(sourceURLs)
		if err != nil {
			exitf("fetch redirects: %v", err)
		}
	} else {
		fmt.Println("warning: no sources/files configured in env.json; generating empty embedded blocklist")
	}

	generatedSource, err := redirects.GenerateGoSource("main", "generatedRedirectBlock", block)
	if err != nil {
		exitf("generate embedded source: %v", err)
	}

	if err := os.WriteFile("generated_hosts.go", generatedSource, 0o644); err != nil {
		exitf("write generated_hosts.go: %v", err)
	}

	targets := splitTargets(*targetsValue)
	if len(targets) == 0 {
		fmt.Println("embedded redirect data refreshed in generated_hosts.go")
		return
	}

	if err := os.MkdirAll(*outputDir, 0o755); err != nil {
		exitf("create output directory: %v", err)
	}

	for _, target := range targets {
		parts := strings.SplitN(target, "/", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			exitf("invalid target %q, expected GOOS/GOARCH", target)
		}

		goos := parts[0]
		goarch := parts[1]
		outputPath := filepath.Join(*outputDir, buildName(*binaryName, goos, goarch, *noProtection))

		args := []string{"build", "-trimpath"}

		ldflags := ""
		if goos == "windows" && !*noProtection {
			ldflags = "-H windowsgui"
		}
		if ldflags != "" {
			args = append(args, "-ldflags", ldflags)
		}

		if *noProtection {
			args = append(args, "-tags", "noprotection")
		}

		args = append(args, "-o", outputPath, ".")

		cmd := exec.Command("go", args...)
		cmd.Env = append(os.Environ(),
			"CGO_ENABLED=0",
			"GOOS="+goos,
			"GOARCH="+goarch,
		)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		if err := cmd.Run(); err != nil {
			exitf("build %s: %v", target, err)
		}

		fmt.Printf("built %s\n", outputPath)
	}
}

func splitTargets(value string) []string {
	raw := strings.Split(value, ",")
	targets := make([]string, 0, len(raw))
	for _, item := range raw {
		item = strings.TrimSpace(item)
		if item != "" {
			targets = append(targets, item)
		}
	}
	return targets
}

func buildName(base, goos, goarch string, noProtection bool) string {
	name := fmt.Sprintf("%s-%s-%s", base, goos, goarch)
	if noProtection {
		name += "-unprotected"
	}
	if goos == "windows" {
		return name + ".exe"
	}
	return name
}

func exitf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func normalizeConfigTorIPs(configPath string, refresh bool, limit int) error {
	content, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}

	var doc map[string]any
	if err := json.Unmarshal(content, &doc); err != nil {
		return err
	}

	current := readStringList(doc["torEntryIPs"])
	current = normalizeIPList(current, limit)

	if refresh {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		fetched, err := fetchTorGuardIPs(ctx, limit)
		if err != nil {
			return err
		}
		current = normalizeIPList(fetched, limit)
		fmt.Printf("refreshed torEntryIPs from Onionoo: %d entries\n", len(current))
	} else {
		fmt.Printf("normalized torEntryIPs: %d entries\n", len(current))
	}

	doc["torEntryIPs"] = current

	updated, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	updated = append(updated, '\n')

	return os.WriteFile(configPath, updated, 0o644)
}

func fetchTorGuardIPs(ctx context.Context, limit int) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, onionooGuardURL, nil)
	if err != nil {
		return nil, err
	}

	client := &http.Client{Timeout: 30 * time.Second}
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
	out := make([]string, 0, 1024)

	for _, relay := range decoded.Relays {
		for _, rawAddr := range relay.OrAddresses {
			addr := strings.TrimSpace(rawAddr)
			if addr == "" {
				continue
			}

			host := addr
			if parsedHost, _, splitErr := net.SplitHostPort(addr); splitErr == nil {
				host = parsedHost
			}

			host = strings.Trim(host, "[]")
			ip := net.ParseIP(host)
			if ip == nil {
				continue
			}

			normalized := ip.String()
			if v4 := ip.To4(); v4 != nil {
				normalized = v4.String()
			}
			if _, exists := seen[normalized]; exists {
				continue
			}
			seen[normalized] = struct{}{}
			out = append(out, normalized)

			if limit > 0 && len(out) >= limit {
				return out, nil
			}
		}
	}

	return out, nil
}

func readStringList(value any) []string {
	raw, ok := value.([]any)
	if !ok {
		return nil
	}

	out := make([]string, 0, len(raw))
	for _, item := range raw {
		text, ok := item.(string)
		if !ok {
			continue
		}
		text = strings.TrimSpace(text)
		if text == "" {
			continue
		}
		out = append(out, text)
	}

	return out
}

func normalizeIPList(in []string, limit int) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))

	for _, item := range in {
		candidate := strings.TrimSpace(item)
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
		if v4 := ip.To4(); v4 != nil {
			normalized = v4.String()
		}
		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)

		if limit > 0 && len(out) >= limit {
			break
		}
	}

	return out
}
