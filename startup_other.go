//go:build !windows && !linux

package main

func ensureStartupRegistration(_ string, _ string, _ string) error {
	return nil
}
