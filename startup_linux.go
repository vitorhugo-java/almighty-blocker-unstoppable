//go:build linux

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func ensureStartupRegistration(serviceName string, executablePath string, stateDir string) error {
	name := strings.TrimSpace(serviceName)
	if name == "" {
		return nil
	}

	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		return fmt.Errorf("create state dir: %w", err)
	}

	unitName := name + ".service"
	unitPath := filepath.Join("/etc/systemd/system", unitName)
	unitContent := systemdUnitContent(executablePath, stateDir)

	existing, err := os.ReadFile(unitPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("read unit file %s: %w", unitPath, err)
		}
		if err := os.WriteFile(unitPath, []byte(unitContent), 0o644); err != nil {
			return fmt.Errorf("write unit file %s: %w", unitPath, err)
		}
	} else if string(existing) != unitContent {
		if err := os.WriteFile(unitPath, []byte(unitContent), 0o644); err != nil {
			return fmt.Errorf("update unit file %s: %w", unitPath, err)
		}
	}

	reload := exec.Command("systemctl", "daemon-reload")
	if output, err := reload.CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %w (%s)", err, strings.TrimSpace(string(output)))
	}

	enabled, err := systemdUnitEnabled(unitName)
	if err != nil {
		return err
	}
	if !enabled {
		enable := exec.Command("systemctl", "enable", unitName)
		if output, err := enable.CombinedOutput(); err != nil {
			return fmt.Errorf("systemctl enable %s: %w (%s)", unitName, err, strings.TrimSpace(string(output)))
		}
	}

	return nil
}

func systemdUnitEnabled(unitName string) (bool, error) {
	cmd := exec.Command("systemctl", "is-enabled", unitName)
	output, err := cmd.CombinedOutput()
	if err == nil {
		return strings.TrimSpace(string(output)) == "enabled", nil
	}

	status := strings.TrimSpace(string(output))
	if status == "disabled" || status == "indirect" || status == "generated" || status == "static" || strings.Contains(status, "not-found") {
		return false, nil
	}

	return false, fmt.Errorf("systemctl is-enabled %s: %w (%s)", unitName, err, status)
}

func systemdUnitContent(executablePath string, stateDir string) string {
	return fmt.Sprintf("[Unit]\nDescription=Almighty Blocker Hosts Enforcer\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nExecStart=%s --role=primary --state-dir=%s\nWorkingDirectory=%s\nRestart=always\nRestartSec=2\nUser=root\nGroup=root\n\n[Install]\nWantedBy=multi-user.target\n", executablePath, stateDir, stateDir)
}
