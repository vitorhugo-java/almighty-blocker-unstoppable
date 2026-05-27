package firewallguard

import (
	"reflect"
	"testing"
)

func TestStaleChunkIndexes(t *testing.T) {
	t.Parallel()

	if got := staleChunkIndexes(3, 5); got != nil {
		t.Fatalf("expected nil when current >= previous, got %#v", got)
	}

	got := staleChunkIndexes(7, 3)
	want := []int{4, 5, 6, 7}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected stale indexes\nwant: %v\ngot:  %v", want, got)
	}
}
