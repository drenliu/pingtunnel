package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pingtunnel.json")
	m := NewManager(path)
	if _, err := m.AddKey("secret-key", "lab", ":4455", "127.0.0.1:22", "tcp"); err != nil {
		t.Fatalf("AddKey: %v", err)
	}

	m2 := NewManager(path)
	if err := m2.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	keys := m2.GetKeys()
	if len(keys) != 1 {
		t.Fatalf("got %d keys, want 1", len(keys))
	}
	if keys[0].Key != "secret-key" || keys[0].Name != "lab" {
		t.Fatalf("unexpected key: %+v", keys[0])
	}
	if len(keys[0].Rules) != 1 || keys[0].Rules[0].ListenAddr != "0.0.0.0:4455" {
		t.Fatalf("unexpected rules: %+v", keys[0].Rules)
	}
}

func TestLoadCorruptConfigDoesNotWipeFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pingtunnel.json")
	corrupt := []byte(`{"keys":[{"id":"x","key":"k"`) // truncated JSON
	if err := os.WriteFile(path, corrupt, 0600); err != nil {
		t.Fatal(err)
	}

	m := NewManager(path)
	if err := m.Load(); err == nil {
		t.Fatal("expected Load error for corrupt config")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(corrupt) {
		t.Fatalf("corrupt file was modified: %q", got)
	}
	if len(m.GetKeys()) != 0 {
		t.Fatalf("manager should stay empty after failed Load")
	}
}

func TestLoadEmptyFileIsError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pingtunnel.json")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	m := NewManager(path)
	if err := m.Load(); err == nil {
		t.Fatal("expected Load error for empty file (truncated-style wipe)")
	}
}

func TestSaveLeavesNoTempFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pingtunnel.json")
	m := NewManager(path)
	if _, err := m.AddKey("k1", "", ":1", "127.0.0.1:2", "tcp"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.AddRule(m.GetKeys()[0].ID, ":2", "127.0.0.1:3", "udp"); err != nil {
		t.Fatal(err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp") || strings.HasPrefix(e.Name(), ".pingtunnel-") {
			t.Fatalf("leftover temp file after save: %s", e.Name())
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cf configFile
	if err := json.Unmarshal(raw, &cf); err != nil {
		t.Fatalf("saved JSON invalid: %v\n%s", err, raw)
	}
	if len(cf.Keys) != 1 || len(cf.Keys[0].Rules) != 2 {
		t.Fatalf("unexpected saved config: %+v", cf)
	}
}

func TestSavePreservesPriorFileWhenTempDirUnwritable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pingtunnel.json")
	good := []byte("{\n  \"keys\": []\n}")
	if err := os.WriteFile(path, good, 0600); err != nil {
		t.Fatal(err)
	}

	// Point manager at a path whose directory cannot create temps.
	ro := filepath.Join(dir, "ro")
	if err := os.Mkdir(ro, 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(ro, 0700) })
	blocked := filepath.Join(ro, "pingtunnel.json")
	if err := os.WriteFile(blocked, good, 0600); err != nil {
		// Parent is 0500: write may fail depending on uid; seed via temp then move.
		_ = os.Chmod(ro, 0700)
		if err := os.WriteFile(blocked, good, 0600); err != nil {
			t.Fatal(err)
		}
		_ = os.Chmod(ro, 0500)
	}

	m := NewManager(blocked)
	m.keys = []*KeyConfig{{ID: "new", Key: "x", Hash: ComputeKeyHash("x")}}
	if err := m.saveLocked(); err == nil {
		t.Fatal("expected saveLocked error when directory is not writable")
	}
	got, err := os.ReadFile(blocked)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(good) {
		t.Fatalf("prior config overwritten despite failed save: %q", got)
	}
}
