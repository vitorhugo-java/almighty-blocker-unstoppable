package torfetch

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
)

func TestFetchGuardIPs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{
  "relays": [
    {"or_addresses": ["1.1.1.1:9001", "2.2.2.2", "invalid"]},
    {"or_addresses": ["[2001:db8::1]:443", "1.1.1.1:9001", "2.2.2.2:443"]}
  ]
}`))
	}))
	defer server.Close()

	got, err := FetchGuardIPs(context.Background(), server.Client(), server.URL, 0)
	if err != nil {
		t.Fatalf("FetchGuardIPs returned error: %v", err)
	}

	want := []string{"1.1.1.1", "2.2.2.2", "2001:db8::1"}
	if !slices.Equal(got, want) {
		t.Fatalf("unexpected IP list\nwant: %v\ngot:  %v", want, got)
	}
}

func TestFetchGuardIPsLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{
  "relays": [
    {"or_addresses": ["3.3.3.3", "1.1.1.1", "2.2.2.2"]}
  ]
}`))
	}))
	defer server.Close()

	got, err := FetchGuardIPs(context.Background(), server.Client(), server.URL, 2)
	if err != nil {
		t.Fatalf("FetchGuardIPs returned error: %v", err)
	}

	want := []string{"1.1.1.1", "2.2.2.2"}
	if !slices.Equal(got, want) {
		t.Fatalf("unexpected IP list\nwant: %v\ngot:  %v", want, got)
	}
}
