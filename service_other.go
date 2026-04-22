//go:build !windows

package main

func runningAsWindowsService() (bool, error) {
	return false, nil
}

func runWindowsService(_ string, _ string) error {
	return nil
}
