package main

import "testing"

func TestNormalizeSocksDialTarget(t *testing.T) {
	if got := normalizeSocksDialTarget(""); got != "" {
		t.Fatalf("empty -> %q", got)
	}
	if got := normalizeSocksDialTarget("  example.com:443 "); got != "example.com:443" {
		t.Fatalf("host:port -> %q", got)
	}
	if got := normalizeSocksDialTarget("10.0.0.5"); got != "10.0.0.5:80" {
		t.Fatalf("ip without port -> %q", got)
	}
}
