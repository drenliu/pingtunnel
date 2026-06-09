package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAuditJSONL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := InitAudit(path); err != nil {
		t.Fatal(err)
	}
	Audit("test.event", map[string]string{"actor_ip": "10.0.0.1", "result": "ok"})
	CloseAudit()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var rec map[string]string
	if err := json.Unmarshal(data[:len(data)-1], &rec); err != nil {
		t.Fatal(err)
	}
	if rec["event"] != "test.event" {
		t.Fatalf("event=%q", rec["event"])
	}
	if rec["actor_ip"] != "10.0.0.1" {
		t.Fatalf("actor_ip=%q", rec["actor_ip"])
	}
	if rec["ts"] == "" {
		t.Fatal("missing ts")
	}
}

func TestAuditRateLimited(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := InitAudit(path); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		AuditRateLimited("k1", "tunnel.key.invalid", map[string]string{"key_hash": "abcd"}, time.Minute)
	}
	CloseAudit()

	lines, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if n := stringsCountNewlines(lines); n != 1 {
		t.Fatalf("want 1 audit line, got %d", n)
	}
}

func stringsCountNewlines(b []byte) int {
	n := 0
	for _, c := range b {
		if c == '\n' {
			n++
		}
	}
	return n
}
