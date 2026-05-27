package dnshijack

import (
	"reflect"
	"testing"
)

func TestSplitDesiredServersSeparatesFamiliesAndDeduplicates(t *testing.T) {
	t.Parallel()

	v4, v6 := splitDesiredServers([]string{
		"1.1.1.1",
		" [2606:4700:4700::1111] ",
		"1.1.1.1",
		"2606:4700:4700::1111",
		"8.8.8.8:53",
		"[2001:4860:4860::8888]:53",
		"invalid",
	})

	if !reflect.DeepEqual(v4, []string{"1.1.1.1", "8.8.8.8"}) {
		t.Fatalf("unexpected IPv4 servers: %#v", v4)
	}
	if !reflect.DeepEqual(v6, []string{"2606:4700:4700::1111", "2001:4860:4860::8888"}) {
		t.Fatalf("unexpected IPv6 servers: %#v", v6)
	}
}

func TestParseDNSServersExtractsByFamily(t *testing.T) {
	t.Parallel()

	output := `
Statically Configured DNS Servers:    1.1.1.1
                                      2606:4700:4700::1111
                                      1.0.0.1
                                      fe80::1%14
`

	if got := parseDNSServers(output, false); !reflect.DeepEqual(got, []string{"1.1.1.1", "1.0.0.1"}) {
		t.Fatalf("unexpected IPv4 parse result: %#v", got)
	}
	if got := parseDNSServers(output, true); !reflect.DeepEqual(got, []string{"2606:4700:4700::1111", "fe80::1"}) {
		t.Fatalf("unexpected IPv6 parse result: %#v", got)
	}
}

func TestSameServerList(t *testing.T) {
	t.Parallel()

	if !sameServerList([]string{"1.1.1.1", "1.0.0.1"}, []string{"1.1.1.1", "1.0.0.1"}) {
		t.Fatalf("expected equal lists to match")
	}
	if sameServerList([]string{"1.1.1.1"}, []string{"1.0.0.1"}) {
		t.Fatalf("expected different lists to not match")
	}
	if sameServerList([]string{"1.1.1.1"}, []string{"1.1.1.1", "1.0.0.1"}) {
		t.Fatalf("expected different length lists to not match")
	}
}
