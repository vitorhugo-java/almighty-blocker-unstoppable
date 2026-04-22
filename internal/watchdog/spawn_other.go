//go:build !windows

package watchdog

import "os/exec"

func configureSpawnCmd(_ *exec.Cmd) {}
