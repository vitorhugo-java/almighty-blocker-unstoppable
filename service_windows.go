//go:build windows

package main

import (
	"context"

	"golang.org/x/sys/windows/svc"
)

func runningAsWindowsService() (bool, error) {
	return svc.IsWindowsService()
}

func runWindowsService(name string, stateDir string) error {
	return svc.Run(name, &windowsService{name: name, stateDir: stateDir})
}

type windowsService struct {
	name     string
	stateDir string
}

func (s *windowsService) Execute(_ []string, requests <-chan svc.ChangeRequest, statuses chan<- svc.Status) (bool, uint32) {
	statuses <- svc.Status{State: svc.StartPending}
	statuses <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runDone := make(chan error, 1)
	go func() {
		runDone <- runApplication(ctx, "primary", s.stateDir, s.name)
	}()

	for {
		select {
		case runErr := <-runDone:
			if runErr != nil {
				return false, 1
			}
			return false, 0
		case req, ok := <-requests:
			if !ok {
				cancel()
				if runErr := <-runDone; runErr != nil {
					return false, 1
				}
				return false, 0
			}

			switch req.Cmd {
			case svc.Interrogate:
				statuses <- req.CurrentStatus
			case svc.Stop, svc.Shutdown:
				statuses <- svc.Status{State: svc.StopPending}
				cancel()
				if runErr := <-runDone; runErr != nil {
					return false, 1
				}
				return false, 0
			default:
			}
		}
	}
}
