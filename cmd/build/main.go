package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"almighty-blocker-unstoppable/internal/redirects"
)

func main() {
	configPath := flag.String("config", "env.json", "path to env json")
	outputDir := flag.String("out", "dist", "directory for built binaries")
	binaryName := flag.String("binary", "almighty-blocker", "base name for output binaries")
	targetsValue := flag.String("targets", "windows/amd64,linux/amd64", "comma-separated GOOS/GOARCH targets")
	noProtection := flag.Bool("no-protection", false, "build with watchdog, system start, and system start monitoring disabled")
	flag.Parse()

	sourceURLs, err := redirects.LoadSources(*configPath)
	if err != nil {
		exitf("load sources: %v", err)
	}

	block, err := redirects.FetchBlock(sourceURLs)
	if err != nil {
		exitf("fetch redirects: %v", err)
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
