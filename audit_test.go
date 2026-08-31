package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
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
	t.Cleanup(CloseAudit)
	for i := 0; i < 5; i++ {
		AuditRateLimited("k1", "tunnel.key.invalid", map[string]string{"key_hash": "abcd"}, time.Minute)
	}

	lines, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if n := stringsCountNewlines(lines); n != 1 {
		t.Fatalf("want 1 audit line, got %d", n)
	}
}

// Regression: invalid-key floods used unique rate keys (hash prefix + addr) and
// grew auditRate without bound → process OOM. Cap must hold under unique-key spray.
func TestAuditRateLimitedBoundsMap(t *testing.T) {
	CloseAudit()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := InitAudit(path); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(CloseAudit)

	interval := time.Hour
	for i := 0; i < auditRateMaxEntries+5000; i++ {
		key := "flood|" + strconv.Itoa(i)
		AuditRateLimited(key, "tunnel.key.invalid", map[string]string{"n": strconv.Itoa(i)}, interval)
	}
	if n := auditRateSize(); n > auditRateMaxEntries {
		t.Fatalf("auditRate size %d exceeds cap %d", n, auditRateMaxEntries)
	}
}

func TestAuditRateLimitedPrunesExpired(t *testing.T) {
	CloseAudit()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := InitAudit(path); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(CloseAudit)

	interval := 20 * time.Millisecond
	for i := 0; i < 100; i++ {
		AuditRateLimited("old|"+strconv.Itoa(i), "tunnel.key.invalid", nil, interval)
	}
	time.Sleep(interval + 10*time.Millisecond)
	// Trigger prune via inserts once at capacity: fill then expire.
	for i := 0; i < auditRateMaxEntries; i++ {
		AuditRateLimited("fill|"+strconv.Itoa(i), "tunnel.key.invalid", nil, time.Hour)
	}
	if n := auditRateSize(); n > auditRateMaxEntries {
		t.Fatalf("auditRate size %d exceeds cap %d", n, auditRateMaxEntries)
	}
	// Expired "old|*" entries should not block new keys after prune.
	AuditRateLimited("fresh", "tunnel.key.invalid", nil, time.Hour)
	if auditRateSize() == 0 {
		t.Fatal("expected rate map to retain entries")
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
