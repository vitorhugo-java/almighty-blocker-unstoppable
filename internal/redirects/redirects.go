package redirects

import (
	"encoding/json"
	"fmt"
	"go/format"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type EnvConfig struct {
	Sources    StringList `json:"sources"`
	SourceList []string `json:"sourceList"`
}

type StringList []string

func (s *StringList) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*s = append((*s)[:0], splitLines(single)...)
		return nil
	}

	var many []string
	if err := json.Unmarshal(data, &many); err == nil {
		*s = append((*s)[:0], many...)
		return nil
	}

	return fmt.Errorf("sources must be a string or array of strings")
}

func LoadSources(path string) ([]string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg EnvConfig
	if err := json.Unmarshal(content, &cfg); err != nil {
		return nil, err
	}

	var sources []string
	for _, item := range cfg.SourceList {
		if trimmed := strings.TrimSpace(item); trimmed != "" {
			sources = append(sources, trimmed)
		}
	}

	for _, item := range cfg.Sources {
		if trimmed := strings.TrimSpace(item); trimmed != "" {
			sources = append(sources, trimmed)
		}
	}

	seen := make(map[string]struct{}, len(sources))
	unique := make([]string, 0, len(sources))
	for _, source := range sources {
		if _, ok := seen[source]; ok {
			continue
		}
		seen[source] = struct{}{}
		unique = append(unique, source)
	}

	if len(unique) == 0 {
		return nil, fmt.Errorf("no source urls configured in %s", path)
	}

	return unique, nil
}

func FetchBlock(urls []string) (string, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	seen := make(map[string]struct{})
	lines := make([]string, 0, 1024)

	for _, rawURL := range urls {
		req, err := http.NewRequest(http.MethodGet, rawURL, nil)
		if err != nil {
			return "", fmt.Errorf("build request for %s: %w", rawURL, err)
		}
		req.Header.Set("User-Agent", "almighty-blocker-builder/1.0")

		resp, err := client.Do(req)
		if err != nil {
			return "", fmt.Errorf("fetch %s: %w", rawURL, err)
		}

		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
		closeErr := resp.Body.Close()
		if readErr != nil {
			return "", fmt.Errorf("read %s: %w", rawURL, readErr)
		}
		if closeErr != nil {
			return "", fmt.Errorf("close %s: %w", rawURL, closeErr)
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return "", fmt.Errorf("fetch %s: unexpected status %s", rawURL, resp.Status)
		}

		parsed, err := ParseLines(string(body))
		if err != nil {
			return "", fmt.Errorf("parse %s: %w", rawURL, err)
		}

		for _, line := range parsed {
			if _, ok := seen[line]; ok {
				continue
			}
			seen[line] = struct{}{}
			lines = append(lines, line)
		}
	}

	if len(lines) == 0 {
		return "", fmt.Errorf("no redirect entries found in configured sources")
	}

	return strings.Join(lines, "\n"), nil
}

func ParseLines(raw string) ([]string, error) {
	seen := map[string]struct{}{}
	lines := make([]string, 0, 1024)

	for _, line := range splitLines(raw) {
		normalized, ok := NormalizeLine(line)
		if !ok {
			continue
		}
		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		lines = append(lines, normalized)
	}

	return lines, nil
}

func NormalizeLine(line string) (string, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", false
	}

	fields := strings.Fields(line)
	if len(fields) == 0 {
		return "", false
	}

	if ip := net.ParseIP(fields[0]); ip != nil {
		hosts := collectHosts(fields[1:])
		if len(hosts) == 0 {
			return "", false
		}
		return ip.String() + " " + strings.Join(hosts, " "), true
	}

	hosts := collectHosts(fields)
	if len(hosts) == 0 {
		return "", false
	}
	return "0.0.0.0 " + strings.Join(hosts, " "), true
}

func BuildManagedContent(existing string, redirects []string, beginMarker string, endMarker string) (string, error) {
	newline := detectNewline(existing)
	missing := missingRedirects(existing, redirects)
	if len(missing) == 0 {
		return existing, nil
	}

	block := beginMarker + newline + strings.Join(missing, newline) + newline + endMarker

	start := strings.Index(existing, beginMarker)
	end := strings.Index(existing, endMarker)

	switch {
	case start == -1 && end == -1:
		base := strings.TrimRight(existing, "\r\n")
		if base == "" {
			return block + newline, nil
		}
		return base + newline + newline + block + newline, nil
	case start >= 0 && end > start:
		insertAt := end
		prefix := existing[:insertAt]
		suffix := existing[insertAt:]
		if !strings.HasSuffix(prefix, newline) {
			prefix += newline
		}
		return prefix + strings.Join(missing, newline) + newline + suffix, nil
	default:
		return "", fmt.Errorf("hosts file contains an incomplete managed block")
	}
}

func HostsPath() (string, error) {
	switch runtime.GOOS {
	case "windows":
		root := os.Getenv("SystemRoot")
		if strings.TrimSpace(root) == "" {
			root = `C:\Windows`
		}
		return filepath.Join(root, "System32", "drivers", "etc", "hosts"), nil
	case "linux":
		return "/etc/hosts", nil
	default:
		return "", fmt.Errorf("unsupported operating system %q", runtime.GOOS)
	}
}

func EnforceHostsLoop(path string, lines []string, beginMarker string, endMarker string) error {
	if err := enforceHosts(path, lines, beginMarker, endMarker); err != nil {
		return err
	}

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for range ticker.C {
		if err := enforceHosts(path, lines, beginMarker, endMarker); err != nil {
			return err
		}
	}

	return nil
}

func enforceHosts(path string, lines []string, beginMarker string, endMarker string) error {
	current, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	updated, err := BuildManagedContent(string(current), lines, beginMarker, endMarker)
	if err != nil {
		return err
	}
	if updated == string(current) {
		return nil
	}

	mode := os.FileMode(0o644)
	if info, statErr := os.Stat(path); statErr == nil {
		mode = info.Mode()
	}

	return os.WriteFile(path, []byte(updated), mode)
}

func GenerateGoSource(packageName string, constName string, value string) ([]byte, error) {
	src := fmt.Sprintf("package %s\n\nconst %s = %q\n", packageName, constName, value)
	return format.Source([]byte(src))
}

func collectHosts(fields []string) []string {
	hosts := make([]string, 0, len(fields))
	for _, field := range fields {
		if strings.HasPrefix(field, "#") {
			break
		}
		hosts = append(hosts, field)
	}
	return hosts
}

func splitLines(value string) []string {
	value = strings.ReplaceAll(value, "\r\n", "\n")
	value = strings.ReplaceAll(value, "\r", "\n")
	return strings.Split(value, "\n")
}

func detectNewline(value string) string {
	if strings.Contains(value, "\r\n") {
		return "\r\n"
	}
	return "\n"
}

func missingRedirects(existing string, redirects []string) []string {
	present := make(map[string]struct{}, len(redirects))
	for _, line := range splitLines(existing) {
		normalized, ok := NormalizeLine(line)
		if !ok {
			continue
		}
		present[normalized] = struct{}{}
	}

	missing := make([]string, 0, len(redirects))
	for _, redirect := range redirects {
		if _, ok := present[redirect]; ok {
			continue
		}
		present[redirect] = struct{}{}
		missing = append(missing, redirect)
	}

	return missing
}
