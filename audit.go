package main

import (
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	auditFile    *os.File
	auditMu      sync.Mutex
	auditEnabled bool

	auditRateMu sync.Mutex
	auditRate   = make(map[string]time.Time)
)

func InitAudit(path string) error {
	path = strings.TrimSpace(path)
	if path == "" || strings.EqualFold(path, "off") {
		return nil
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	auditFile = f
	auditEnabled = true
	return nil
}

func CloseAudit() {
	auditMu.Lock()
	defer auditMu.Unlock()
	if auditFile != nil {
		auditFile.Close()
		auditFile = nil
	}
	auditEnabled = false
}

func Audit(event string, fields map[string]string) {
	if !auditEnabled || event == "" {
		return
	}
	rec := make(map[string]string, len(fields)+2)
	rec["ts"] = time.Now().UTC().Format(time.RFC3339Nano)
	rec["event"] = event
	for k, v := range fields {
		if v != "" {
			rec[k] = v
		}
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return
	}
	auditMu.Lock()
	defer auditMu.Unlock()
	if auditFile != nil {
		_, _ = auditFile.Write(b)
		_, _ = auditFile.Write([]byte("\n"))
	}
}

// AuditRateLimited logs at most once per rateKey within interval (reduces flood on repeated events).
func AuditRateLimited(rateKey, event string, fields map[string]string, interval time.Duration) {
	if rateKey == "" {
		Audit(event, fields)
		return
	}
	now := time.Now()
	auditRateMu.Lock()
	last, ok := auditRate[rateKey]
	if ok && now.Sub(last) < interval {
		auditRateMu.Unlock()
		return
	}
	auditRate[rateKey] = now
	auditRateMu.Unlock()
	Audit(event, fields)
}

func hashPrefix(h [16]byte) string {
	return hex.EncodeToString(h[:4])
}

func auditKeyFields(mgr *Manager, hash [16]byte) map[string]string {
	f := map[string]string{"key_hash": hashPrefix(hash)}
	if mgr == nil {
		return f
	}
	kc := mgr.ValidateKey(hash)
	if kc == nil {
		return f
	}
	f["key_id"] = kc.ID
	if kc.Name != "" {
		f["key_name"] = kc.Name
	}
	return f
}

func mergeFields(base map[string]string, extra map[string]string) map[string]string {
	out := make(map[string]string, len(base)+len(extra))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

func remoteIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.Index(xff, ","); i >= 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func addrString(a net.Addr) string {
	if a == nil {
		return ""
	}
	return a.String()
}

func keyAuditLabel(kc *KeyConfig) string {
	if kc == nil {
		return "unknown"
	}
	if kc.Name != "" {
		return kc.Name + " (id=" + kc.ID + ")"
	}
	return "id=" + kc.ID
}
