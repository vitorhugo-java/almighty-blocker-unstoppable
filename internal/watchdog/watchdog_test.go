package watchdog

import (
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
