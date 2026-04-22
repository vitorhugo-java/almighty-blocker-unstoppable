package watchdog

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type Role string

const (
	RolePrimary  Role = "primary"
	RoleWatchdog Role = "watchdog"
)

const (
	heartbeatInterval = time.Second
	staleAfter        = 3 * time.Second
)

type Watchdog struct {
	Role              Role
	PartnerRole       Role
	ExecutablePath    string
	StateDir          string
	HeartbeatInterval time.Duration
	StaleAfter        time.Duration
}

type state struct {
	PID       int   `json:"pid"`
	UpdatedAt int64 `json:"updatedAt"`
}

func New(role Role, executablePath string, stateDir string) (*Watchdog, error) {
	partner, err := partnerRole(role)
	if err != nil {
		return nil, err
	}

	if strings.TrimSpace(stateDir) == "" {
		stateDir = filepath.Join(os.TempDir(), "almighty-blocker-unstoppable")
	}

	return &Watchdog{
		Role:              role,
		PartnerRole:       partner,
		ExecutablePath:    executablePath,
		StateDir:          stateDir,
		HeartbeatInterval: heartbeatInterval,
		StaleAfter:        staleAfter,
	}, nil
}

func ParseRole(value string) (Role, error) {
	role := Role(strings.TrimSpace(strings.ToLower(value)))
	switch role {
	case RolePrimary, RoleWatchdog:
		return role, nil
	default:
		return "", fmt.Errorf("unsupported role %q", value)
	}
}

func (w *Watchdog) Run(ctx context.Context, workload func(context.Context) error) error {
	if err := os.MkdirAll(w.StateDir, 0o755); err != nil {
		return err
	}

	if err := w.claimRole(); err != nil {
		return err
	}
	defer w.removeOwnState()

	if err := w.writeOwnState(); err != nil {
		return err
	}
	if err := w.ensurePartner(); err != nil {
		return err
	}

	workDone := make(chan error, 1)
	if workload != nil {
		go func() {
			workDone <- workload(ctx)
		}()
	}

	ticker := time.NewTicker(w.HeartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-workDone:
			return err
		case <-ticker.C:
			if err := w.writeOwnState(); err != nil {
				return err
			}
			if err := w.ensurePartner(); err != nil {
				return err
			}
		}
	}
}

func (w *Watchdog) claimRole() error {
	current, err := w.readState(w.Role)
	if err != nil {
		return err
	}
	if current == nil {
		return nil
	}
	if current.PID == os.Getpid() {
		return nil
	}
	if stateFresh(*current, w.StaleAfter) {
		return fmt.Errorf("%s process is already active with pid %d", w.Role, current.PID)
	}
	return nil
}

func (w *Watchdog) ensurePartner() error {
	partner, err := w.readState(w.PartnerRole)
	if err != nil {
		return err
	}
	if partner != nil && stateFresh(*partner, w.StaleAfter) {
		return nil
	}
	return w.spawn(w.PartnerRole)
}

func (w *Watchdog) spawn(role Role) error {
	cmd := exec.Command(w.ExecutablePath, "--role="+string(role), "--state-dir="+w.StateDir)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	configureSpawnCmd(cmd)
	return cmd.Start()
}

func (w *Watchdog) writeOwnState() error {
	current := state{
		PID:       os.Getpid(),
		UpdatedAt: time.Now().UnixNano(),
	}

	data, err := json.Marshal(current)
	if err != nil {
		return err
	}

	return os.WriteFile(w.statePath(w.Role), data, 0o644)
}

func (w *Watchdog) readState(role Role) (*state, error) {
	data, err := os.ReadFile(w.statePath(role))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var current state
	if err := json.Unmarshal(data, &current); err != nil {
		return nil, err
	}
	return &current, nil
}

func (w *Watchdog) removeOwnState() {
	current, err := w.readState(w.Role)
	if err != nil || current == nil {
		return
	}
	if current.PID != os.Getpid() {
		return
	}
	_ = os.Remove(w.statePath(w.Role))
}

func (w *Watchdog) statePath(role Role) string {
	return filepath.Join(w.StateDir, string(role)+".json")
}

func partnerRole(role Role) (Role, error) {
	switch role {
	case RolePrimary:
		return RoleWatchdog, nil
	case RoleWatchdog:
		return RolePrimary, nil
	default:
		return "", fmt.Errorf("unsupported role %q", role)
	}
}

func stateFresh(current state, staleAfter time.Duration) bool {
	return time.Since(time.Unix(0, current.UpdatedAt)) <= staleAfter
}
