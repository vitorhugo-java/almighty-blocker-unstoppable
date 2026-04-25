//go:build windows && !noprotection

package main

import (
	"fmt"
	"os/exec"
	"strings"
	"syscall"
)

func ensureStartupRegistration(serviceName string, executablePath string, stateDir string) error {
	name := strings.TrimSpace(serviceName)
	if name == "" {
		return nil
	}

	binPath := fmt.Sprintf("\"%s\" --role=primary --state-dir=\"%s\" --service-name=\"%s\"", executablePath, stateDir, name)

	exists, err := windowsServiceExists(name)
	if err != nil {
		return err
	}

	if !exists {
		create := exec.Command("sc.exe", "create", name, "binPath=", binPath, "start=", "auto", "DisplayName=", "Almighty Blocker")
		hideWindow(create)
		if output, err := create.CombinedOutput(); err != nil {
			return fmt.Errorf("create service %q: %w (%s)", name, err, strings.TrimSpace(string(output)))
		}

		describe := exec.Command("sc.exe", "description", name, "Keeps hosts redirects enforced in background")
		hideWindow(describe)
		if output, err := describe.CombinedOutput(); err != nil {
			return fmt.Errorf("set description for service %q: %w (%s)", name, err, strings.TrimSpace(string(output)))
		}
	} else {
		config := exec.Command("sc.exe", "config", name, "binPath=", binPath, "start=", "auto")
		hideWindow(config)
		if output, err := config.CombinedOutput(); err != nil {
			return fmt.Errorf("update service %q startup config: %w (%s)", name, err, strings.TrimSpace(string(output)))
		}
	}

	return nil
}

func windowsServiceExists(serviceName string) (bool, error) {
	query := exec.Command("sc.exe", "query", serviceName)
	hideWindow(query)
	output, err := query.CombinedOutput()
	if err == nil {
		return true, nil
	}

	text := strings.ToUpper(string(output))
	if strings.Contains(text, "FAILED 1060") {
		return false, nil
	}

	return false, fmt.Errorf("query service %q: %w (%s)", serviceName, err, strings.TrimSpace(string(output)))
}

func hideWindow(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
}
