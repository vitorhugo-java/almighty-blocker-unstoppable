//go:build windows

package watchdog

import (
	"os/exec"
	"syscall"
)

func configureSpawnCmd(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
}
