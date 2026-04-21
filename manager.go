package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type ForwardRule struct {
	ID         string `json:"id"`
	ListenAddr string `json:"listen_addr"`
	TargetAddr string `json:"target_addr"`
	Protocol   string `json:"protocol,omitempty"` // "tcp" (default) or "udp"
}

type KeyConfig struct {
	ID       string         `json:"id"`
	Key      string         `json:"key"`
	Name     string         `json:"name"`
	AllowAll bool           `json:"allow_all"`
	Hash     [16]byte       `json:"-"`
	Rules    []*ForwardRule `json:"rules"`
	TotalIn  uint64         `json:"total_in"`
	TotalOut uint64         `json:"total_out"`
}

type configFile struct {
	Keys []*KeyConfig `json:"keys"`
}

type keyTraffic struct {
	bytesIn  uint64 // atomic — session bytes received (client→server)
	bytesOut uint64 // atomic — session bytes sent (server→client)
	prevIn   uint64
	prevOut  uint64
	speedIn  uint64 // atomic — bytes/sec
	speedOut uint64 // atomic — bytes/sec
}

type Manager struct {
	keys   []*KeyConfig
	byHash map[[16]byte]*KeyConfig
	path   string
	mu     sync.RWMutex

	traffic   map[[16]byte]*keyTraffic
	trafficMu sync.Mutex
}

func NewManager(path string) *Manager {
	return &Manager{
		path:    path,
		byHash:  make(map[[16]byte]*KeyConfig),
		traffic: make(map[[16]byte]*keyTraffic),
	}
}

// ── traffic tracking ──

func (m *Manager) getTraffic(hash [16]byte) *keyTraffic {
	m.trafficMu.Lock()
	t := m.traffic[hash]
	if t == nil {
		t = &keyTraffic{}
		m.traffic[hash] = t
	}
	m.trafficMu.Unlock()
	return t
}

func (m *Manager) RecordIn(hash [16]byte, n int) {
	atomic.AddUint64(&m.getTraffic(hash).bytesIn, uint64(n))
}

func (m *Manager) RecordOut(hash [16]byte, n int) {
	atomic.AddUint64(&m.getTraffic(hash).bytesOut, uint64(n))
}

// GetTraffic returns current speed and un-flushed session bytes.
func (m *Manager) GetTraffic(hash [16]byte) (speedIn, speedOut, sessionIn, sessionOut uint64) {
	m.trafficMu.Lock()
	t := m.traffic[hash]
	m.trafficMu.Unlock()
	if t == nil {
		return
	}
	speedIn = atomic.LoadUint64(&t.speedIn)
	speedOut = atomic.LoadUint64(&t.speedOut)
	sessionIn = atomic.LoadUint64(&t.bytesIn)
	sessionOut = atomic.LoadUint64(&t.bytesOut)
	return
}

func (m *Manager) updateSpeeds() {
	m.trafficMu.Lock()
	defer m.trafficMu.Unlock()
	for _, t := range m.traffic {
		curIn := atomic.LoadUint64(&t.bytesIn)
		curOut := atomic.LoadUint64(&t.bytesOut)
		atomic.StoreUint64(&t.speedIn, curIn-t.prevIn)
		atomic.StoreUint64(&t.speedOut, curOut-t.prevOut)
		t.prevIn = curIn
		t.prevOut = curOut
	}
}

func (m *Manager) flushTraffic() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.trafficMu.Lock()
	changed := false
	for hash, t := range m.traffic {
		kc := m.byHash[hash]
		if kc == nil {
			continue
		}
		dIn := atomic.SwapUint64(&t.bytesIn, 0)
		dOut := atomic.SwapUint64(&t.bytesOut, 0)
		if dIn > 0 || dOut > 0 {
			kc.TotalIn += dIn
			kc.TotalOut += dOut
			t.prevIn = 0
			t.prevOut = 0
			changed = true
		}
	}
	m.trafficMu.Unlock()
	if changed {
		m.saveLocked()
	}
}

func (m *Manager) StartTrafficLoop(done <-chan struct{}) {
	go func() {
		speedTick := time.NewTicker(time.Second)
		flushTick := time.NewTicker(30 * time.Second)
		defer speedTick.Stop()
		defer flushTick.Stop()
		for {
			select {
			case <-speedTick.C:
				m.updateSpeeds()
			case <-flushTick.C:
				m.flushTraffic()
			case <-done:
				m.flushTraffic()
				log.Println("[manager] traffic flushed on shutdown")
				return
			}
		}
	}()
}

// ── persistence ──

func (m *Manager) Load() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	data, err := os.ReadFile(m.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var cf configFile
	if err := json.Unmarshal(data, &cf); err != nil {
		return err
	}
	m.keys = cf.Keys
	m.rebuildIndex()
	m.saveLocked()
	return nil
}

func (m *Manager) Save() error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.saveLocked()
}

func (m *Manager) saveLocked() error {
	if m.path == "" {
		return nil
	}
	cf := configFile{Keys: m.keys}
	data, err := json.MarshalIndent(cf, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(m.path, data, 0600)
}

func (m *Manager) rebuildIndex() {
	m.byHash = make(map[[16]byte]*KeyConfig, len(m.keys))
	for _, kc := range m.keys {
		kc.Hash = ComputeKeyHash(kc.Key)
		m.byHash[kc.Hash] = kc
		for _, r := range kc.Rules {
			r.ListenAddr = normalizeListenAddr(r.ListenAddr)
			r.TargetAddr = normalizeTargetAddr(r.TargetAddr)
			r.Protocol = normalizeProtocol(r.Protocol)
		}
	}
}

// ── key operations ──

func (m *Manager) ValidateKey(hash [16]byte) *KeyConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.byHash[hash]
}

func (m *Manager) IsRuleAllowed(hash [16]byte, listenAddr, targetAddr, protocol string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	kc := m.byHash[hash]
	if kc == nil {
		return false
	}
	if kc.AllowAll {
		return true
	}
	listenAddr = normalizeListenAddr(listenAddr)
	targetAddr = normalizeTargetAddr(targetAddr)
	protocol = normalizeProtocol(protocol)
	for _, r := range kc.Rules {
		if r.ListenAddr == listenAddr && r.TargetAddr == targetAddr && r.Protocol == protocol {
			return true
		}
	}
	return false
}

func (m *Manager) GetKeys() []*KeyConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*KeyConfig, len(m.keys))
	copy(out, m.keys)
	return out
}

func (m *Manager) EnsureKey(key, name string) *KeyConfig {
	m.mu.Lock()
	defer m.mu.Unlock()

	hash := ComputeKeyHash(key)
	if kc, ok := m.byHash[hash]; ok {
		return kc
	}
	kc := &KeyConfig{ID: randID(), Key: key, Name: name, AllowAll: true, Hash: hash}
	m.keys = append(m.keys, kc)
	m.byHash[hash] = kc
	return kc
}

func (m *Manager) AddKey(key, name, listenAddr, targetAddr, protocol string) (*KeyConfig, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	hash := ComputeKeyHash(key)
	if _, ok := m.byHash[hash]; ok {
		return nil, fmt.Errorf("key already exists")
	}
	listenAddr = normalizeListenAddr(listenAddr)
	targetAddr = normalizeTargetAddr(targetAddr)
	protocol = normalizeProtocol(protocol)
	kc := &KeyConfig{ID: randID(), Key: key, Name: name, Hash: hash}
	if listenAddr != "" && targetAddr != "" {
		kc.Rules = []*ForwardRule{{ID: randID(), ListenAddr: listenAddr, TargetAddr: targetAddr, Protocol: protocol}}
	}
	m.keys = append(m.keys, kc)
	m.byHash[hash] = kc
	m.saveLocked()
	return kc, nil
}

func (m *Manager) RemoveKey(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for i, kc := range m.keys {
		if kc.ID == id {
			delete(m.byHash, kc.Hash)
			m.keys = append(m.keys[:i], m.keys[i+1:]...)
			m.saveLocked()
			return nil
		}
	}
	return fmt.Errorf("key not found")
}

func (m *Manager) AddRule(keyID, listenAddr, targetAddr, protocol string) (*ForwardRule, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	listenAddr = normalizeListenAddr(listenAddr)
	targetAddr = normalizeTargetAddr(targetAddr)
	protocol = normalizeProtocol(protocol)
	for _, kc := range m.keys {
		if kc.ID == keyID {
			for _, r := range kc.Rules {
				if r.ListenAddr == listenAddr && r.TargetAddr == targetAddr && r.Protocol == protocol {
					return nil, fmt.Errorf("rule already exists")
				}
			}
			r := &ForwardRule{ID: randID(), ListenAddr: listenAddr, TargetAddr: targetAddr, Protocol: protocol}
			kc.Rules = append(kc.Rules, r)
			m.saveLocked()
			return r, nil
		}
	}
	return nil, fmt.Errorf("key not found")
}

func (m *Manager) RemoveRule(keyID, ruleID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, kc := range m.keys {
		if kc.ID == keyID {
			for i, r := range kc.Rules {
				if r.ID == ruleID {
					kc.Rules = append(kc.Rules[:i], kc.Rules[i+1:]...)
					m.saveLocked()
					return nil
				}
			}
			return fmt.Errorf("rule not found")
		}
	}
	return fmt.Errorf("key not found")
}

// normalizeListenAddr ensures a listen address has host:port form.
// "4455" → "0.0.0.0:4455", ":4455" → "0.0.0.0:4455", "0.0.0.0:4455" unchanged.
func normalizeListenAddr(addr string) string {
	if addr == "" {
		return addr
	}
	hasColon := false
	for i := 0; i < len(addr); i++ {
		if addr[i] == ':' {
			hasColon = true
			if i == 0 {
				return "0.0.0.0" + addr
			}
			break
		}
	}
	if !hasColon {
		return "0.0.0.0:" + addr
	}
	return addr
}

// normalizeTargetAddr ensures a target address has host:port form.
// "22" → "127.0.0.1:22", ":22" → "127.0.0.1:22", "192.168.1.1:22" unchanged.
func normalizeTargetAddr(addr string) string {
	if addr == "" {
		return addr
	}
	hasColon := false
	for i := 0; i < len(addr); i++ {
		if addr[i] == ':' {
			hasColon = true
			if i == 0 {
				return "127.0.0.1" + addr
			}
			break
		}
	}
	if !hasColon {
		return "127.0.0.1:" + addr
	}
	return addr
}

func randID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func normalizeProtocol(p string) string {
	switch strings.ToLower(strings.TrimSpace(p)) {
	case "udp":
		return "udp"
	default:
		return "tcp"
	}
}

// ListenerMapKey returns a stable map key for server listener bookkeeping (proto + listen address).
func ListenerMapKey(protocol, listenAddr string) string {
	return normalizeProtocol(protocol) + "/" + normalizeListenAddr(listenAddr)
}
