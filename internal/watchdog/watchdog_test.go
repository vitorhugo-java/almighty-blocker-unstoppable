package watchdog

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseRole(t *testing.T) {
	t.Parallel()

	role, err := ParseRole("PRIMARY")
	if err != nil {
		t.Fatalf("ParseRole returned error: %v", err)
	}
	if role != RolePrimary {
		t.Fatalf("expected %q, got %q", RolePrimary, role)
	}
}

func TestPartnerRole(t *testing.T) {
	t.Parallel()

	partner, err := partnerRole(RolePrimary)
	if err != nil {
		t.Fatalf("partnerRole returned error: %v", err)
	}
	if partner != RoleWatchdog {
		t.Fatalf("expected %q, got %q", RoleWatchdog, partner)
	}
}

func TestStateFresh(t *testing.T) {
	t.Parallel()

	fresh := state{UpdatedAt: time.Now().Add(-time.Second).UnixNano()}
	if !stateFresh(fresh, 3*time.Second) {
		t.Fatal("expected fresh state to be considered alive")
	}

	stale := state{UpdatedAt: time.Now().Add(-5 * time.Second).UnixNano()}
	if stateFresh(stale, 3*time.Second) {
		t.Fatal("expected stale state to be considered dead")
	}
}

func TestClaimRoleUsesExplicitLock(t *testing.T) {
	tempDir := t.TempDir()
	wd, err := New(RolePrimary, "/tmp/bin", tempDir)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	wd.processExistsFunc = func(pid int) bool { return pid == 9999 }

	if err := os.WriteFile(filepath.Join(tempDir, "primary.lock"), []byte("9999"), 0o644); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	err = wd.claimRole()
	if err == nil {
		t.Fatal("expected claimRole to fail when lock owner is alive")
	}
}

func TestEnsurePartnerSkipsDuplicateSpawnWhilePartnerStarts(t *testing.T) {
	wd, err := New(RolePrimary, "/tmp/bin", t.TempDir())
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	now := time.Now()
	wd.StartupGrace = 5 * time.Second
	wd.nowFunc = func() time.Time { return now }
	wd.processExistsFunc = func(pid int) bool { return pid == 1234 }

	spawnCalls := 0
	wd.spawnFunc = func(Role) (int, error) {
		spawnCalls++
		return 1234, nil
	}

	if err := wd.ensurePartner(); err != nil {
		t.Fatalf("first ensurePartner returned error: %v", err)
	}
	if err := wd.ensurePartner(); err != nil {
		t.Fatalf("second ensurePartner returned error: %v", err)
	}
	if spawnCalls != 1 {
		t.Fatalf("expected one spawn call while partner starts, got %d", spawnCalls)
	}
}

func TestEnsurePartnerDoesNotRespawnAliveStalePartner(t *testing.T) {
	tempDir := t.TempDir()
	wd, err := New(RoleWatchdog, "/tmp/bin", tempDir)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	wd.processExistsFunc = func(pid int) bool { return pid == 4242 }
	wd.spawnFunc = func(Role) (int, error) {
		t.Fatal("spawn should not be called when partner process is alive")
		return 0, nil
	}

	stale := state{
		PID:       4242,
		UpdatedAt: time.Now().Add(-10 * time.Second).UnixNano(),
	}
	data, err := json.Marshal(stale)
	if err != nil {
		t.Fatalf("Marshal returned error: %v", err)
	}
	if err := os.MkdirAll(tempDir, 0o755); err != nil {
		t.Fatalf("MkdirAll returned error: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tempDir, "primary.json"), data, 0o644); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	if err := wd.ensurePartner(); err != nil {
		t.Fatalf("ensurePartner returned error: %v", err)
	}
}
