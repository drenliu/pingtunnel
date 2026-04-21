package main

import (
	_ "embed"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

//go:embed web.html
var webHTML string

type StatusInfo struct {
	ICMPIn      uint64   `json:"icmp_in"`
	ICMPOut     uint64   `json:"icmp_out"`
	BadKey      uint64   `json:"bad_key"`
	ActiveConns int      `json:"active_conns"`
	Listeners   []string `json:"listeners"`
	ClientAddr  string   `json:"client_addr"`
}

func StartWeb(addr, password string, mgr *Manager, srv *Server) {
	ws := &webServer{
		mgr:      mgr,
		srv:      srv,
		password: password,
		sessions: make(map[string]time.Time),
	}
	log.Printf("[web] management UI on http://%s  (user: admin)", addr)
	go func() {
		if err := http.ListenAndServe(addr, ws); err != nil {
			log.Printf("[web] listen: %v", err)
		}
	}()
}

type webServer struct {
	mgr      *Manager
	srv      *Server
	password string
	sessions map[string]time.Time
	sessMu   sync.Mutex
}

func (ws *webServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path

	if p == "/" || p == "/index.html" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(webHTML))
		return
	}

	w.Header().Set("Content-Type", "application/json")

	if p == "/api/login" && r.Method == "POST" {
		ws.apiLogin(w, r)
		return
	}

	if !ws.authenticated(r) {
		w.WriteHeader(401)
		json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
		return
	}

	switch {
	case p == "/api/status" && r.Method == "GET":
		ws.apiStatus(w)
	case p == "/api/keys" && r.Method == "GET":
		ws.apiListKeys(w)
	case p == "/api/keys" && r.Method == "POST":
		ws.apiAddKey(w, r)
	case strings.HasPrefix(p, "/api/keys/"):
		ws.apiKeyRoutes(w, r, strings.TrimPrefix(p, "/api/keys/"))
	default:
		http.NotFound(w, r)
	}
}

// ── auth ──

func (ws *webServer) apiLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, "invalid request", 400)
		return
	}
	if req.Username != "admin" || req.Password != ws.password {
		jsonErr(w, "invalid username or password", 401)
		return
	}

	token := randID() + randID()
	ws.sessMu.Lock()
	now := time.Now()
	ws.sessions[token] = now.Add(24 * time.Hour)
	for k, v := range ws.sessions {
		if now.After(v) {
			delete(ws.sessions, k)
		}
	}
	ws.sessMu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     "pt_session",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   86400,
	})
	json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

func (ws *webServer) authenticated(r *http.Request) bool {
	c, err := r.Cookie("pt_session")
	if err != nil {
		return false
	}
	ws.sessMu.Lock()
	exp, ok := ws.sessions[c.Value]
	ws.sessMu.Unlock()
	return ok && time.Now().Before(exp)
}

// ── api handlers ──

func (ws *webServer) apiStatus(w http.ResponseWriter) {
	s := ws.srv
	s.mu.RLock()
	listeners := make([]string, 0, len(s.listenersTCP)+len(s.listenersUDP))
	for k := range s.listenersTCP {
		listeners = append(listeners, k)
	}
	for k := range s.listenersUDP {
		listeners = append(listeners, k)
	}
	conns := len(s.connections)
	s.mu.RUnlock()

	s.clientMu.RLock()
	ca := ""
	if s.clientAddr != nil {
		ca = s.clientAddr.String()
	}
	s.clientMu.RUnlock()

	json.NewEncoder(w).Encode(StatusInfo{
		ICMPIn:      atomic.LoadUint64(&s.stats.icmpIn),
		ICMPOut:     atomic.LoadUint64(&s.stats.icmpOut),
		BadKey:      atomic.LoadUint64(&s.stats.badKey),
		ActiveConns: conns,
		Listeners:   listeners,
		ClientAddr:  ca,
	})
}

func (ws *webServer) apiListKeys(w http.ResponseWriter) {
	keys := ws.mgr.GetKeys()
	connsByKey := ws.srv.GetConnsByKey()
	type keyResp struct {
		ID       string         `json:"id"`
		Key      string         `json:"key"`
		Name     string         `json:"name"`
		AllowAll bool           `json:"allow_all"`
		Rules    []*ForwardRule `json:"rules"`
		TotalIn  uint64         `json:"total_in"`
		TotalOut uint64         `json:"total_out"`
		SpeedIn  uint64         `json:"speed_in"`
		SpeedOut uint64         `json:"speed_out"`
		Conns    []ConnInfo     `json:"conns"`
	}
	resp := make([]keyResp, len(keys))
	for i, k := range keys {
		si, so, sessIn, sessOut := ws.mgr.GetTraffic(k.Hash)
		rules := k.Rules
		if rules == nil {
			rules = make([]*ForwardRule, 0)
		}
		conns := connsByKey[k.Hash]
		if conns == nil {
			conns = make([]ConnInfo, 0)
		}
		resp[i] = keyResp{
			ID:       k.ID,
			Key:      k.Key,
			Name:     k.Name,
			AllowAll: k.AllowAll,
			Rules:    rules,
			TotalIn:  k.TotalIn + sessIn,
			TotalOut: k.TotalOut + sessOut,
			SpeedIn:  si,
			SpeedOut: so,
			Conns:    conns,
		}
	}
	json.NewEncoder(w).Encode(resp)
}

func (ws *webServer) apiAddKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Key        string `json:"key"`
		Name       string `json:"name"`
		ListenAddr string `json:"listen_addr"`
		TargetAddr string `json:"target_addr"`
		Protocol   string `json:"protocol"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, "invalid JSON", 400)
		return
	}
	if req.Key == "" {
		jsonErr(w, "key is required", 400)
		return
	}
	if req.Name == "" {
		req.Name = "Unnamed"
	}
	kc, err := ws.mgr.AddKey(req.Key, req.Name, req.ListenAddr, req.TargetAddr, req.Protocol)
	if err != nil {
		jsonErr(w, err.Error(), 400)
		return
	}
	ws.srv.StartConfiguredListeners()
	json.NewEncoder(w).Encode(kc)
}

func (ws *webServer) apiKeyRoutes(w http.ResponseWriter, r *http.Request, rest string) {
	parts := strings.Split(rest, "/")

	if len(parts) == 1 && r.Method == "DELETE" {
		if err := ws.mgr.RemoveKey(parts[0]); err != nil {
			jsonErr(w, err.Error(), 404)
			return
		}
		json.NewEncoder(w).Encode(map[string]bool{"ok": true})
		return
	}

	if len(parts) == 2 && parts[1] == "rules" && r.Method == "POST" {
		var req struct {
			ListenAddr string `json:"listen_addr"`
			TargetAddr string `json:"target_addr"`
			Protocol   string `json:"protocol"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonErr(w, "invalid JSON", 400)
			return
		}
		if req.ListenAddr == "" || req.TargetAddr == "" {
			jsonErr(w, "listen_addr and target_addr are required", 400)
			return
		}
		rule, err := ws.mgr.AddRule(parts[0], req.ListenAddr, req.TargetAddr, req.Protocol)
		if err != nil {
			jsonErr(w, err.Error(), 400)
			return
		}
		ws.srv.StartConfiguredListeners()
		json.NewEncoder(w).Encode(rule)
		return
	}

	if len(parts) == 3 && parts[1] == "rules" && r.Method == "DELETE" {
		if err := ws.mgr.RemoveRule(parts[0], parts[2]); err != nil {
			jsonErr(w, err.Error(), 404)
			return
		}
		json.NewEncoder(w).Encode(map[string]bool{"ok": true})
		return
	}

	http.NotFound(w, r)
}

func jsonErr(w http.ResponseWriter, msg string, code int) {
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
