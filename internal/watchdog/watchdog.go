package watchdog

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
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
	// startupGrace is the maximum wait for a freshly spawned partner to publish heartbeat.
	startupGrace = 6 * time.Second
	// lockRetryAttempts retries lock acquisition once after stale lock cleanup.
	lockRetryAttempts = 2
)

type Watchdog struct {
	Role              Role
	PartnerRole       Role
	ExecutablePath    string
	StateDir          string
	HeartbeatInterval time.Duration
	StaleAfter        time.Duration
	StartupGrace      time.Duration

	spawnFunc         func(Role) (int, error)
	processExistsFunc func(int) bool
	nowFunc           func() time.Time
	pendingSpawnMu    sync.Mutex
	pendingSpawnPID   int
	pendingSpawnUntil time.Time
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
		StartupGrace:      startupGrace,
		processExistsFunc: processExists,
		nowFunc:           time.Now,
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
	defer func() {
		w.removeOwnState()
		w.releaseRole()
	}()

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
	if err := w.claimRoleLock(); err != nil {
		return err
	}

	current, err := w.readState(w.Role)
	if err != nil {
		w.releaseRole()
		return err
	}
	if current == nil {
		return nil
	}
	if current.PID == os.Getpid() {
		return nil
	}
	if w.processExists(current.PID) {
		w.releaseRole()
		return fmt.Errorf("%s process is already active with pid %d", w.Role, current.PID)
	}
	return nil
}

func (w *Watchdog) ensurePartner() error {
	partner, err := w.readState(w.PartnerRole)
	if err != nil {
		return err
	}
	partnerAlive := partner != nil && w.processExists(partner.PID)
	partnerFresh := partner != nil && stateFresh(*partner, w.StaleAfter)
	if partnerAlive && partnerFresh {
		w.clearPendingSpawn()
		return nil
	}

	now := w.now()
	pendingPID, pendingUntil := w.pendingSpawn()
	if pendingPID != 0 {
		if now.Before(pendingUntil) && w.processExists(pendingPID) {
			return nil
		}
		w.clearPendingSpawn()
	}
	if partnerAlive {
		return nil
	}

	locked, err := w.claimSpawnLock(w.PartnerRole)
	if err != nil {
		return err
	}
	if !locked {
		return nil
	}
	defer w.releaseSpawnLock(w.PartnerRole)

	partner, err = w.readState(w.PartnerRole)
	if err != nil {
		return err
	}
	if partner != nil && w.processExists(partner.PID) {
		w.clearPendingSpawn()
		return nil
	}

	pid, err := w.spawn(w.PartnerRole)
	if err != nil {
		return err
	}
	w.setPendingSpawn(pid, now.Add(w.StartupGrace))
	return nil
}

func (w *Watchdog) spawn(role Role) (int, error) {
	if w.spawnFunc != nil {
		return w.spawnFunc(role)
	}
	cmd := exec.Command(w.ExecutablePath, "--role="+string(role), "--state-dir="+w.StateDir)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	configureSpawnCmd(cmd)
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	return cmd.Process.Pid, nil
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

func (w *Watchdog) lockPath(role Role) string {
	return filepath.Join(w.StateDir, string(role)+".lock")
}

func (w *Watchdog) spawnLockPath(role Role) string {
	return filepath.Join(w.StateDir, string(role)+".spawn.lock")
}

func (w *Watchdog) claimRoleLock() error {
	lockPath := w.lockPath(w.Role)

	for attempt := 0; attempt < lockRetryAttempts; attempt++ {
		f, err := os.OpenFile(lockPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if err == nil {
			_, writeErr := f.WriteString(strconv.Itoa(os.Getpid()))
			closeErr := f.Close()
			if writeErr != nil {
				_ = os.Remove(lockPath)
				return writeErr
			}
			if closeErr != nil {
				_ = os.Remove(lockPath)
				return closeErr
			}
			return nil
		}
		if !os.IsExist(err) {
			return err
		}

		lockPID, readErr := readPIDFile(lockPath)
		if readErr != nil || lockPID <= 0 || !w.processExists(lockPID) {
			if removeErr := os.Remove(lockPath); removeErr != nil && !os.IsNotExist(removeErr) {
				return removeErr
			}
			continue
		}
		if lockPID == os.Getpid() {
			return nil
		}
		return fmt.Errorf("%s process is already active with pid %d", w.Role, lockPID)
	}

	return fmt.Errorf("failed to claim %s role lock", w.Role)
}

func (w *Watchdog) releaseRole() {
	lockPath := w.lockPath(w.Role)
	lockPID, err := readPIDFile(lockPath)
	if err != nil || lockPID != os.Getpid() {
		return
	}
	_ = os.Remove(lockPath)
}

// claimSpawnLock acquires the partner spawn lock for the given role.
// It returns (true, nil) when the current process owns the lock, (false, nil)
// when another live process already owns it, and an error only for I/O failures.
func (w *Watchdog) claimSpawnLock(role Role) (bool, error) {
	lockPath := w.spawnLockPath(role)

	for attempt := 0; attempt < lockRetryAttempts; attempt++ {
		f, err := os.OpenFile(lockPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if err == nil {
			_, writeErr := f.WriteString(strconv.Itoa(os.Getpid()))
			closeErr := f.Close()
			if writeErr != nil {
				_ = os.Remove(lockPath)
				return false, writeErr
			}
			if closeErr != nil {
				_ = os.Remove(lockPath)
				return false, closeErr
			}
			return true, nil
		}
		if !os.IsExist(err) {
			return false, err
		}

		lockPID, readErr := readPIDFile(lockPath)
		if readErr != nil || lockPID <= 0 || !w.processExists(lockPID) {
			if removeErr := os.Remove(lockPath); removeErr != nil && !os.IsNotExist(removeErr) {
				return false, removeErr
			}
			continue
		}
		if lockPID == os.Getpid() {
			return true, nil
		}
		return false, nil
	}

	return false, fmt.Errorf("failed to claim spawn lock for %s role", role)
}

// releaseSpawnLock releases a partner spawn lock only when the current process
// is the lock owner. Non-owner and missing-lock cases are ignored.
func (w *Watchdog) releaseSpawnLock(role Role) {
	lockPath := w.spawnLockPath(role)
	lockPID, err := readPIDFile(lockPath)
	if err != nil || lockPID != os.Getpid() {
		return
	}
	_ = os.Remove(lockPath)
}

func readPIDFile(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}

	return strconv.Atoi(strings.TrimSpace(string(data)))
}

func (w *Watchdog) processExists(pid int) bool {
	if w.processExistsFunc != nil {
		return w.processExistsFunc(pid)
	}
	return processExists(pid)
}

func (w *Watchdog) now() time.Time {
	if w.nowFunc != nil {
		return w.nowFunc()
	}
	return time.Now()
}

func (w *Watchdog) clearPendingSpawn() {
	w.pendingSpawnMu.Lock()
	defer w.pendingSpawnMu.Unlock()
	w.pendingSpawnPID = 0
	w.pendingSpawnUntil = time.Time{}
}

func (w *Watchdog) setPendingSpawn(pid int, until time.Time) {
	w.pendingSpawnMu.Lock()
	defer w.pendingSpawnMu.Unlock()
	w.pendingSpawnPID = pid
	w.pendingSpawnUntil = until
}

func (w *Watchdog) pendingSpawn() (int, time.Time) {
	w.pendingSpawnMu.Lock()
	defer w.pendingSpawnMu.Unlock()
	return w.pendingSpawnPID, w.pendingSpawnUntil
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
