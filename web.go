package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

//go:embed web.html
var webHTML string

func webPageHTML(defaultServerIP string) string {
	s := strings.TrimSpace(defaultServerIP)
	if s == "" {
		return webHTML
	}
	b, err := json.Marshal(s)
	if err != nil {
		return webHTML
	}
	return strings.Replace(webHTML, "</head>", "<script>var PT_WEB_SERVER_IP="+string(b)+";</script>\n</head>", 1)
}

type StatusInfo struct {
	ICMPIn      uint64   `json:"icmp_in"`
	ICMPOut     uint64   `json:"icmp_out"`
	BadKey      uint64   `json:"bad_key"`
	ActiveConns int      `json:"active_conns"`
	Listeners   []string `json:"listeners"`
}

func StartWeb(addr, password string, mgr *Manager, srv *Server, webServerIP string) {
	ws := &webServer{
		mgr:      mgr,
		srv:      srv,
		password: password,
		sessions: make(map[string]time.Time),
		htmlPage: webPageHTML(webServerIP),
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
	htmlPage string
}

func (ws *webServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path

	if p == "/" || p == "/index.html" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(ws.htmlPage))
		return
	}

	w.Header().Set("Content-Type", "application/json")

	if p == "/api/login" && r.Method == "POST" {
		ws.apiLogin(w, r)
		return
	}

	if !ws.authenticated(r) {
		Audit("web.auth.denied", map[string]string{
			"actor_ip": remoteIP(r),
			"method":   r.Method,
			"path":     p,
		})
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
		Audit("web.login.failure", map[string]string{
			"actor_ip": remoteIP(r),
			"username": req.Username,
			"result":   "denied",
		})
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
	Audit("web.login.success", map[string]string{
		"actor_ip": remoteIP(r),
		"username": "admin",
		"result":   "ok",
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
	ws.srv.pruneStaleICMPPeers()
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

	json.NewEncoder(w).Encode(StatusInfo{
		ICMPIn:      atomic.LoadUint64(&s.stats.tunIn),
		ICMPOut:     atomic.LoadUint64(&s.stats.tunOut),
		BadKey:      atomic.LoadUint64(&s.stats.badKey),
		ActiveConns: conns,
		Listeners:   listeners,
	})
}

func (ws *webServer) apiListKeys(w http.ResponseWriter) {
	ws.srv.pruneStaleICMPPeers()
	keys := ws.mgr.GetKeys()
	connsByKey := ws.srv.GetConnsByKey()
	type ruleWithTunnel struct {
		ID             string `json:"id"`
		ListenAddr     string `json:"listen_addr"`
		TargetAddr     string `json:"target_addr"`
		Protocol       string `json:"protocol,omitempty"`
		IcmpOnline     bool   `json:"icmp_online"`
		IcmpClientAddr string `json:"icmp_client_addr,omitempty"`
	}
	type keyResp struct {
		ID       string           `json:"id"`
		Key      string           `json:"key"`
		Name     string           `json:"name"`
		AllowAll bool             `json:"allow_all"`
		Rules    []ruleWithTunnel `json:"rules"`
		TotalIn  uint64           `json:"total_in"`
		TotalOut uint64           `json:"total_out"`
		SpeedIn  uint64           `json:"speed_in"`
		SpeedOut uint64           `json:"speed_out"`
		Conns    []ConnInfo       `json:"conns"`
	}
	resp := make([]keyResp, len(keys))
	for i, k := range keys {
		si, so, sessIn, sessOut := ws.mgr.GetTraffic(k.Hash)
		rules := k.Rules
		if rules == nil {
			rules = make([]*ForwardRule, 0)
		}
		rulesOut := make([]ruleWithTunnel, len(rules))
		for j, r := range rules {
			rulesOut[j] = ruleWithTunnel{
				ID:             r.ID,
				ListenAddr:     r.ListenAddr,
				TargetAddr:     r.TargetAddr,
				Protocol:       r.Protocol,
				IcmpOnline:     ws.srv.IsRuleTunnelOnline(k.Hash, r),
				IcmpClientAddr: ws.srv.ICMPClientAddrForRule(k.Hash, r),
			}
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
			Rules:    rulesOut,
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
	kc, err := ws.mgr.AddKey(req.Key, req.Name, req.ListenAddr, req.TargetAddr, req.Protocol)
	if err != nil {
		jsonErr(w, err.Error(), 400)
		return
	}
	ws.srv.StartConfiguredListeners()
	Audit("web.key.create", mergeFields(auditKeyFields(ws.mgr, kc.Hash), map[string]string{
		"actor_ip":    remoteIP(r),
		"listen_addr": req.ListenAddr,
		"target_addr": req.TargetAddr,
		"protocol":    req.Protocol,
		"result":      "ok",
	}))
	json.NewEncoder(w).Encode(kc)
}

func (ws *webServer) apiKeyRoutes(w http.ResponseWriter, r *http.Request, rest string) {
	parts := strings.Split(rest, "/")

	if len(parts) == 1 && r.Method == "DELETE" {
		kc := ws.mgr.GetKeyByID(parts[0])
		if err := ws.mgr.RemoveKey(parts[0]); err != nil {
			jsonErr(w, err.Error(), 404)
			return
		}
		// RemoveKey only updates config; tear down the orphaned listeners/sessions
		// so deleted keys stop accepting traffic and free listen ports for reuse.
		if kc != nil {
			mapKeys := make([]string, 0, len(kc.Rules))
			for _, rule := range kc.Rules {
				mapKeys = append(mapKeys, ListenerMapKey(rule.Protocol, rule.ListenAddr))
			}
			ws.srv.StopListenersForRemovedKey(kc.Hash, mapKeys)
		}
		fields := map[string]string{"actor_ip": remoteIP(r), "key_id": parts[0], "result": "ok"}
		if kc != nil {
			fields["key_hash"] = hashPrefix(kc.Hash)
			if kc.Name != "" {
				fields["key_name"] = kc.Name
			}
		}
		Audit("web.key.delete", fields)
		json.NewEncoder(w).Encode(map[string]bool{"ok": true})
		return
	}

	if len(parts) == 1 && r.Method == "PATCH" {
		var req struct {
			Key  *string `json:"key"`
			Name *string `json:"name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonErr(w, "invalid JSON", 400)
			return
		}
		hashChanged, prevHash, err := ws.mgr.UpdateKey(parts[0], req.Key, req.Name)
		if err != nil {
			code := 400
			if err.Error() == "key not found" {
				code = 404
			}
			jsonErr(w, err.Error(), code)
			return
		}
		if hashChanged {
			ws.srv.RestartListenersAfterKeyHashChange(prevHash, parts[0])
		} else {
			ws.srv.StartConfiguredListeners()
		}
		kc := ws.mgr.GetKeyByID(parts[0])
		fields := map[string]string{
			"actor_ip":     remoteIP(r),
			"key_id":       parts[0],
			"hash_changed": fmt.Sprintf("%v", hashChanged),
			"result":       "ok",
		}
		if kc != nil {
			fields["key_hash"] = hashPrefix(kc.Hash)
			if kc.Name != "" {
				fields["key_name"] = kc.Name
			}
		}
		if hashChanged {
			fields["prev_key_hash"] = hashPrefix(prevHash)
		}
		Audit("web.key.update", fields)
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
		kc := ws.mgr.GetKeyByID(parts[0])
		fields := map[string]string{
			"actor_ip":    remoteIP(r),
			"key_id":      parts[0],
			"rule_id":     rule.ID,
			"listen_addr": rule.ListenAddr,
			"target_addr": rule.TargetAddr,
			"protocol":    rule.Protocol,
			"result":      "ok",
		}
		if kc != nil {
			fields["key_hash"] = hashPrefix(kc.Hash)
		}
		Audit("web.rule.create", fields)
		json.NewEncoder(w).Encode(rule)
		return
	}

	if len(parts) == 3 && parts[1] == "rules" && r.Method == "DELETE" {
		// Capture listen map key before removal so we can stop the live listener.
		// UpdateRule already restarts listeners; DELETE previously left them running,
		// so revoked rules kept forwarding until process restart.
		kc := ws.mgr.GetKeyByID(parts[0])
		var mapKey string
		var keyHash [16]byte
		if kc != nil {
			keyHash = kc.Hash
			for _, rule := range kc.Rules {
				if rule.ID == parts[2] {
					mapKey = ListenerMapKey(rule.Protocol, rule.ListenAddr)
					break
				}
			}
		}
		if err := ws.mgr.RemoveRule(parts[0], parts[2]); err != nil {
			jsonErr(w, err.Error(), 404)
			return
		}
		if mapKey != "" {
			ws.srv.RestartListenersAfterRuleChange(keyHash, mapKey, "")
		}
		kc = ws.mgr.GetKeyByID(parts[0])
		fields := map[string]string{
			"actor_ip": remoteIP(r),
			"key_id":   parts[0],
			"rule_id":  parts[2],
			"result":   "ok",
		}
		if kc != nil {
			fields["key_hash"] = hashPrefix(kc.Hash)
		}
		Audit("web.rule.delete", fields)
		json.NewEncoder(w).Encode(map[string]bool{"ok": true})
		return
	}

	if len(parts) == 3 && parts[1] == "rules" && r.Method == "PATCH" {
		var req struct {
			ListenAddr string `json:"listen_addr"`
			TargetAddr string `json:"target_addr"`
			Protocol   string `json:"protocol"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonErr(w, "invalid JSON", 400)
			return
		}
		if strings.TrimSpace(req.ListenAddr) == "" || strings.TrimSpace(req.TargetAddr) == "" {
			jsonErr(w, "listen_addr and target_addr are required", 400)
			return
		}
		rule, oldMapKey, newMapKey, err := ws.mgr.UpdateRule(parts[0], parts[2], req.ListenAddr, req.TargetAddr, req.Protocol)
		if err != nil {
			code := 400
			if err.Error() == "key not found" || err.Error() == "rule not found" {
				code = 404
			}
			jsonErr(w, err.Error(), code)
			return
		}
		kc := ws.mgr.GetKeyByID(parts[0])
		if kc != nil {
			ws.srv.RestartListenersAfterRuleChange(kc.Hash, oldMapKey, newMapKey)
		} else {
			ws.srv.StartConfiguredListeners()
		}
		fields := map[string]string{
			"actor_ip":    remoteIP(r),
			"key_id":      parts[0],
			"rule_id":     rule.ID,
			"listen_addr": rule.ListenAddr,
			"target_addr": rule.TargetAddr,
			"protocol":    rule.Protocol,
			"result":      "ok",
		}
		if kc != nil {
			fields["key_hash"] = hashPrefix(kc.Hash)
		}
		Audit("web.rule.update", fields)
		json.NewEncoder(w).Encode(rule)
		return
	}

	http.NotFound(w, r)
}

func jsonErr(w http.ResponseWriter, msg string, code int) {
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
