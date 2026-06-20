//go:build windows

package watchdog

import (
	"os/exec"
	"syscall"
)

// createNoWindow (CREATE_NO_WINDOW) tells Windows never to allocate a console
// for the child process. Combined with the GUI subsystem of the protected build
// this guarantees that spawning the partner process never flashes a terminal.
const createNoWindow = 0x08000000

func configureSpawnCmd(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
}
