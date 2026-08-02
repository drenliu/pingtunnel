package main

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func waitForTCPListener(s *Server, mapKey string, want bool, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		s.mu.RLock()
		_, ok := s.listenersTCP[mapKey]
		s.mu.RUnlock()
		if ok == want {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

func freeListenAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

func TestRestartListenersAfterRuleChangeStopsDeletedRule(t *testing.T) {
	mgr := NewManager("")
	listen := freeListenAddr(t)
	kc, err := mgr.AddKey("rule-del-key", "t", listen, "127.0.0.1:9", "tcp")
	if err != nil {
		t.Fatal(err)
	}
	if len(kc.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(kc.Rules))
	}
	ruleID := kc.Rules[0].ID
	mapKey := ListenerMapKey("tcp", listen)

	s := NewServer(mgr, false, "dns", ":0", "c.pingt.local", "")
	defer s.Close()
	s.StartConfiguredListeners()
	if !waitForTCPListener(s, mapKey, true, 2*time.Second) {
		t.Fatalf("listener %s did not start", mapKey)
	}

	if err := mgr.RemoveRule(kc.ID, ruleID); err != nil {
		t.Fatal(err)
	}
	s.RestartListenersAfterRuleChange(kc.Hash, mapKey, "")

	if !waitForTCPListener(s, mapKey, false, 2*time.Second) {
		t.Fatalf("listener %s still running after rule delete restart", mapKey)
	}

	// Port must be reusable by a replacement rule/key.
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		t.Fatalf("listen port still held after rule delete: %v", err)
	}
	ln.Close()
}

func TestStopListenersForRemovedKeyFreesPort(t *testing.T) {
	mgr := NewManager("")
	listen := freeListenAddr(t)
	kc, err := mgr.AddKey("key-del-key", "t", listen, "127.0.0.1:9", "tcp")
	if err != nil {
		t.Fatal(err)
	}
	mapKey := ListenerMapKey("tcp", listen)

	s := NewServer(mgr, false, "dns", ":0", "c.pingt.local", "")
	defer s.Close()
	s.StartConfiguredListeners()
	if !waitForTCPListener(s, mapKey, true, 2*time.Second) {
		t.Fatalf("listener %s did not start", mapKey)
	}

	mapKeys := []string{mapKey}
	hash := kc.Hash
	if err := mgr.RemoveKey(kc.ID); err != nil {
		t.Fatal(err)
	}
	s.StopListenersForRemovedKey(hash, mapKeys)

	if !waitForTCPListener(s, mapKey, false, 2*time.Second) {
		t.Fatalf("listener %s still running after key delete", mapKey)
	}

	// A new key with the same listen port must be able to bind.
	kc2, err := mgr.AddKey("key-del-key-2", "t2", listen, "127.0.0.1:9", "tcp")
	if err != nil {
		t.Fatal(err)
	}
	s.StartConfiguredListeners()
	if !waitForTCPListener(s, mapKey, true, 2*time.Second) {
		t.Fatalf("replacement key %s listener did not start", kc2.ID)
	}
}

func TestWebDeleteRuleStopsListener(t *testing.T) {
	mgr := NewManager("")
	listen := freeListenAddr(t)
	kc, err := mgr.AddKey("web-rule-del", "t", listen, "127.0.0.1:9", "tcp")
	if err != nil {
		t.Fatal(err)
	}
	ruleID := kc.Rules[0].ID
	mapKey := ListenerMapKey("tcp", listen)

	s := NewServer(mgr, false, "dns", ":0", "c.pingt.local", "")
	defer s.Close()
	s.StartConfiguredListeners()
	if !waitForTCPListener(s, mapKey, true, 2*time.Second) {
		t.Fatalf("listener %s did not start", mapKey)
	}

	ws := &webServer{
		mgr:      mgr,
		srv:      s,
		password: "test",
		sessions: map[string]time.Time{"tok": time.Now().Add(time.Hour)},
	}
	req := httptest.NewRequest(http.MethodDelete, "/api/keys/"+kc.ID+"/rules/"+ruleID, nil)
	req.AddCookie(&http.Cookie{Name: "pt_session", Value: "tok"})
	rr := httptest.NewRecorder()
	ws.ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("DELETE rule status %d body %s", rr.Code, rr.Body.String())
	}

	if !waitForTCPListener(s, mapKey, false, 2*time.Second) {
		t.Fatalf("web DELETE rule left listener %s running", mapKey)
	}
}

func TestWebDeleteKeyStopsListener(t *testing.T) {
	mgr := NewManager("")
	listen := freeListenAddr(t)
	kc, err := mgr.AddKey("web-key-del", "t", listen, "127.0.0.1:9", "tcp")
	if err != nil {
		t.Fatal(err)
	}
	mapKey := ListenerMapKey("tcp", listen)

	s := NewServer(mgr, false, "dns", ":0", "c.pingt.local", "")
	defer s.Close()
	s.StartConfiguredListeners()
	if !waitForTCPListener(s, mapKey, true, 2*time.Second) {
		t.Fatalf("listener %s did not start", mapKey)
	}

	ws := &webServer{
		mgr:      mgr,
		srv:      s,
		password: "test",
		sessions: map[string]time.Time{"tok": time.Now().Add(time.Hour)},
	}
	req := httptest.NewRequest(http.MethodDelete, "/api/keys/"+kc.ID, nil)
	req.AddCookie(&http.Cookie{Name: "pt_session", Value: "tok"})
	rr := httptest.NewRecorder()
	ws.ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("DELETE key status %d body %s", rr.Code, rr.Body.String())
	}
	var resp map[string]bool
	if err := json.NewDecoder(bytes.NewReader(rr.Body.Bytes())).Decode(&resp); err != nil || !resp["ok"] {
		t.Fatalf("unexpected body %s", rr.Body.String())
	}

	if !waitForTCPListener(s, mapKey, false, 2*time.Second) {
		t.Fatalf("web DELETE key left listener %s running", mapKey)
	}
}
