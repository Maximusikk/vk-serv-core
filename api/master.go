package main

// Этап 3: мастер (админ-сервер). Контракт — docs/API.md «Этап 3 — мастер /master/*».
//
// Одна подписка = ключ с одним external_id на каждой активной ноде. К нодам мастер
// ходит тем же pinned-клиентом, что и бот (master_client.go): пин проверяется до
// отправки master-token, без обходных путей мимо HTTP. Авторизация /master/* —
// только admin-token (админка мастера).

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	masterMode = "master"

	subPending = "pending"
	subActive  = "active"
	subFailed  = "failed"
)

// nodeRow — строка таблицы servers.
type nodeRow struct {
	ID          int64
	API         string
	Pin         string
	MasterToken string
	Name        string
	Status      string
	LastSeen    int64
	Version     string
	Capacity    int64
	Since       int64
}

const nodeCols = `id, api, pin, master_token, COALESCE(name,''), status, last_seen, COALESCE(version,''), capacity, since`

func scanNode(sc interface{ Scan(...any) error }) (nodeRow, error) {
	var n nodeRow
	err := sc.Scan(&n.ID, &n.API, &n.Pin, &n.MasterToken, &n.Name, &n.Status, &n.LastSeen, &n.Version, &n.Capacity, &n.Since)
	return n, err
}

func (s *Server) listNodes() ([]nodeRow, error) {
	rows, err := s.db.Query(`SELECT ` + nodeCols + ` FROM servers ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []nodeRow
	for rows.Next() {
		n, err := scanNode(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func (s *Server) getNodeByAPI(api string) (nodeRow, error) {
	return scanNode(s.db.QueryRow(`SELECT `+nodeCols+` FROM servers WHERE api = ?`, api))
}

// upsertNode добавляет/обновляет ноду по api (join и саморегистрация).
func (s *Server) upsertNode(n nodeRow) (int64, error) {
	_, err := s.db.Exec(`
		INSERT INTO servers (api, pin, master_token, name, status, last_seen, version, capacity, since)
		VALUES (?, ?, ?, ?, 'active', ?, ?, ?, 0)
		ON CONFLICT(api) DO UPDATE SET pin = excluded.pin, master_token = excluded.master_token,
			name = excluded.name, status = 'active', last_seen = excluded.last_seen,
			version = excluded.version, capacity = excluded.capacity`,
		n.API, n.Pin, n.MasterToken, n.Name, time.Now().Unix(), n.Version, n.Capacity)
	if err != nil {
		return 0, err
	}
	var id int64
	err = s.db.QueryRow(`SELECT id FROM servers WHERE api = ?`, n.API).Scan(&id)
	return id, err
}

// ── join-токены (3.7): одноразовые, 1 час, в памяти ─────────────────────────────

type joinToken struct {
	expiresAt time.Time
}

var joinTokens struct {
	mu     sync.Mutex
	tokens map[string]joinToken
}

func init() { joinTokens.tokens = map[string]joinToken{} }

func (s *Server) newJoinToken() (string, int64, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", 0, err
	}
	tok := hex.EncodeToString(b)
	exp := time.Now().Add(time.Hour)
	joinTokens.mu.Lock()
	joinTokens.tokens[tok] = joinToken{expiresAt: exp}
	joinTokens.mu.Unlock()
	return tok, exp.Unix(), nil
}

func (s *Server) consumeJoinToken(tok string) bool {
	joinTokens.mu.Lock()
	defer joinTokens.mu.Unlock()
	jt, ok := joinTokens.tokens[tok]
	if !ok || time.Now().After(jt.expiresAt) {
		if ok {
			delete(joinTokens.tokens, tok) // просроченный — убрать
		}
		return false
	}
	delete(joinTokens.tokens, tok) // одноразовый
	return true
}

// ── хендлеры ─────────────────────────────────────────────────────────────────────

func (s *Server) requireMaster(w http.ResponseWriter) bool {
	if s.cfg.Mode != masterMode {
		jsonError(w, "этот API не мастер (запускай с -mode master)", http.StatusNotImplemented)
		return false
	}
	return true
}

// handleMasterJoinTokens — POST /master/join-tokens (3.7).
func (s *Server) handleMasterJoinTokens(w http.ResponseWriter, r *http.Request) {
	if !s.requireMaster(w) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	tok, exp, err := s.newJoinToken()
	if err != nil {
		jsonError(w, "crypto error", http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]any{"token": tok, "expires_at": exp})
}

// handleMasterJoin — POST /master/join (3.7): регистрация ноды по одноразовому токену.
func (s *Server) handleMasterJoin(w http.ResponseWriter, r *http.Request) {
	if !s.requireMaster(w) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Token       string `json:"token"`
		API         string `json:"api"`
		Pin         string `json:"pin"`
		MasterToken string `json:"master_token"`
		Name        string `json:"name"`
		Version     string `json:"version"`
		Capacity    int64  `json:"capacity"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	req.API = strings.TrimSpace(req.API)
	req.Pin = strings.TrimSpace(req.Pin)
	req.MasterToken = strings.TrimSpace(req.MasterToken)
	if req.API == "" || req.MasterToken == "" {
		jsonError(w, "api and master_token are required", http.StatusBadRequest)
		return
	}
	if parsePinHex(req.Pin) == "" {
		jsonError(w, "pin must be 64 hex chars", http.StatusBadRequest)
		return
	}
	if !s.consumeJoinToken(req.Token) {
		jsonError(w, "join token invalid or expired", http.StatusForbidden)
		return
	}
	id, err := s.upsertNode(nodeRow{
		API: req.API, Pin: parsePinHex(req.Pin), MasterToken: req.MasterToken,
		Name: req.Name, Version: req.Version, Capacity: req.Capacity,
	})
	if err != nil {
		jsonError(w, "db error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	log.Printf("[master] нода зарегистрирована: %s (%s)", req.API, req.Name)
	jsonOK(w, map[string]any{"status": "registered", "server_id": id})
}

// handleMasterListServers — GET /master/servers.
func (s *Server) handleMasterListServers(w http.ResponseWriter, r *http.Request) {
	if !s.requireMaster(w) {
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	nodes, err := s.listNodes()
	if err != nil {
		jsonError(w, "db error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	type srvInfo struct {
		ID       int64  `json:"id"`
		API      string `json:"api"`
		Name     string `json:"name"`
		Status   string `json:"status"`
		LastSeen int64  `json:"last_seen"`
		Version  string `json:"version"`
		Capacity int64  `json:"capacity"`
		Since    int64  `json:"since"`
	}
	out := make([]srvInfo, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, srvInfo{n.ID, n.API, n.Name, n.Status, n.LastSeen, n.Version, n.Capacity, n.Since})
	}
	jsonOK(w, map[string]any{"servers": out})
}

// handleMasterCreateSub — POST /master/subscriptions (3.3): раскатка ключа на ноды.
func (s *Server) handleMasterCreateSub(w http.ResponseWriter, r *http.Request) {
	if !s.requireMaster(w) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ExternalID  string `json:"external_id"`
		Name        string `json:"name"`
		BytesLimit  int64  `json:"bytes_limit"`
		ExpiresDays int64  `json:"expires_days"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	req.ExternalID = strings.TrimSpace(req.ExternalID)
	if req.ExternalID == "" || req.ExpiresDays <= 0 {
		jsonError(w, "external_id and expires_days are required", http.StatusBadRequest)
		return
	}
	if req.BytesLimit < 0 {
		jsonError(w, "bytes_limit must be >= 0", http.StatusBadRequest)
		return
	}

	res, err := s.db.Exec(`INSERT INTO subscriptions (external_id, name, bytes_limit, expires_at)
		VALUES (?, ?, ?, 0)`, req.ExternalID, req.Name, req.BytesLimit)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			jsonError(w, "subscription with this external_id already exists", http.StatusConflict)
			return
		}
		jsonError(w, "db error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	subID, _ := res.LastInsertId()

	delivered := s.dispatchSubscription(subID, req.BytesLimit, req.ExpiresDays)
	jsonOK(w, s.subscriptionResponse(subID, delivered))
}

// dispatchSubscription создаёт ключ на каждой активной ноде и фиксирует статус
// доставки. Ошибки не глотаются: текст уходит в subscription_servers.error.
// Возвращает количество успешно доставленных.
func (s *Server) dispatchSubscription(subID int64, bytesLimit, expiresDays int64) int {
	var sub struct {
		ExternalID string
		Name       string
	}
	if err := s.db.QueryRow(`SELECT external_id, COALESCE(name,'') FROM subscriptions WHERE id = ?`, subID).
		Scan(&sub.ExternalID, &sub.Name); err != nil {
		log.Printf("[master] подписка %d: %v", subID, err)
		return 0
	}

	nodes, err := s.listNodes()
	if err != nil {
		log.Printf("[master] подписка %d: ноды: %v", subID, err)
		return 0
	}

	// Пометить все ноды pending (включая новые ноды, добавленные после создания)
	for _, n := range nodes {
		s.db.Exec(`INSERT INTO subscription_servers (sub_id, server_id, status) VALUES (?, ?, 'pending')
			ON CONFLICT(sub_id, server_id) DO NOTHING`, subID, n.ID)
	}

	delivered := 0
	for _, n := range nodes {
		var st, keyID, errText string
		if n.Status != "active" {
			st, errText = subPending, ""
		} else {
			var resp struct {
				Key string `json:"key"`
			}
			err := s.nodeCall(n, http.MethodPost, "/v1/admin/keys/create", map[string]any{
				"expires_days": expiresDays,
				"start":        "on_activation",
				"bytes_limit":  bytesLimit,
				"local_limit":  bytesLimit, // 3.3: страховка на ноде, если мастер пропал
				"external_id":  sub.ExternalID,
			}, &resp)
			switch {
			case err == nil && resp.Key != "":
				st, keyID = subActive, resp.Key
				delivered++
			case err == nil:
				st, errText = subFailed, "нода вернула пустой key"
			default:
				st, errText = subFailed, err.Error()
			}
		}
		if _, err := s.db.Exec(`
			INSERT INTO subscription_servers (sub_id, server_id, key_id, status, error)
			VALUES (?, ?, ?, ?, ?)
			ON CONFLICT(sub_id, server_id) DO UPDATE SET key_id = excluded.key_id,
				status = excluded.status, error = excluded.error`,
			subID, n.ID, keyID, st, errText); err != nil {
			log.Printf("[master] подписка %d: статус ноды %s: %v", subID, n.API, err)
		}
	}
	return delivered
}

// subscriptionRow — данные подписки для ответов и bundle.
type subRow struct {
	ID         int64
	ExternalID string
	Name       string
	BytesLimit int64
	ExpiresAt  int64
	BytesUsed  int64
	RevokedAt  sql.NullInt64
}

const subCols = `id, external_id, COALESCE(name,''), bytes_limit, expires_at, bytes_used, revoked_at`

// subServers — доставка ключей подписки по нодам (для ответа и bundle).
type subServerRow struct {
	ServerID int64
	API      string
	KeyID    string
	Status   string
	Error    string
}

func (s *Server) subServers(subID int64) ([]subServerRow, error) {
	rows, err := s.db.Query(`
		SELECT ss.server_id, s.api, ss.key_id, ss.status, ss.error
		FROM subscription_servers ss JOIN servers s ON s.id = ss.server_id
		WHERE ss.sub_id = ? ORDER BY ss.server_id`, subID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []subServerRow
	for rows.Next() {
		var r subServerRow
		if err := rows.Scan(&r.ServerID, &r.API, &r.KeyID, &r.Status, &r.Error); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// masterBundle — vkturn://bundle/… по 00d §1.3 из доставленных ключей (тот же
// формат, что make_bundle в Python: {v:1, n, s:[{api,pin,key,name}], limit?}).
func (s *Server) masterBundle(sub subRow, servers []subServerRow) string {
	type srv struct {
		API  string `json:"api"`
		Pin  string `json:"pin"`
		Key  string `json:"key"`
		Name string `json:"name"`
	}
	type payload struct {
		V     int    `json:"v"`
		N     string `json:"n"`
		S     []srv  `json:"s"`
		Limit *int64 `json:"limit,omitempty"`
	}
	p := payload{V: 1, N: sub.Name}
	for _, ss := range servers {
		if ss.Status != subActive || ss.KeyID == "" {
			continue
		}
		pin := ""
		s.db.QueryRow(`SELECT pin FROM servers WHERE id = ?`, ss.ServerID).Scan(&pin)
		p.S = append(p.S, srv{API: ss.API, Pin: pin, Key: ss.KeyID, Name: ""})
	}
	if len(p.S) == 0 {
		return ""
	}
	if sub.BytesLimit > 0 {
		p.Limit = &sub.BytesLimit
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return ""
	}
	return "vkturn://bundle/" + base64.RawURLEncoding.EncodeToString(raw)
}

func (s *Server) subscriptionResponse(subID int64, delivered int) map[string]any {
	var sub subRow
	if err := scanSub(s.db.QueryRow(`SELECT `+subCols+` FROM subscriptions WHERE id = ?`, subID), &sub); err != nil {
		return map[string]any{"error": "db error: " + err.Error()}
	}
	servers, _ := s.subServers(subID)
	type srvOut struct {
		ServerID int64  `json:"server_id"`
		API      string `json:"api"`
		KeyID    string `json:"key_id"`
		Status   string `json:"status"`
		Error    string `json:"error,omitempty"`
	}
	srvList := make([]srvOut, 0, len(servers))
	for _, ss := range servers {
		srvList = append(srvList, srvOut{ss.ServerID, ss.API, ss.KeyID, ss.Status, ss.Error})
	}
	resp := map[string]any{
		"id":          sub.ID,
		"external_id": sub.ExternalID,
		"name":        sub.Name,
		"bytes_limit": sub.BytesLimit,
		"bytes_used":  sub.BytesUsed,
		"expires_at":  sub.ExpiresAt,
		"delivered":   delivered,
		"servers":     srvList,
	}
	if b := s.masterBundle(sub, servers); b != "" {
		resp["bundle"] = b
	} else {
		resp["bundle"] = nil
	}
	return resp
}

func scanSub(sc interface{ Scan(...any) error }, out *subRow) error {
	return sc.Scan(&out.ID, &out.ExternalID, &out.Name, &out.BytesLimit, &out.ExpiresAt, &out.BytesUsed, &out.RevokedAt)
}

// handleMasterListSubs — GET /master/subscriptions.
func (s *Server) handleMasterListSubs(w http.ResponseWriter, r *http.Request) {
	if !s.requireMaster(w) {
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rows, err := s.db.Query(`SELECT ` + subCols + ` FROM subscriptions ORDER BY id`)
	if err != nil {
		jsonError(w, "db error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	// Материализуем выборку ДО вложенных запросов: OpenDB ставит MaxOpenConns(1),
	// вложенный Query при открытом rows заблокировался бы навсегда.
	var all []subRow
	for rows.Next() {
		var sub subRow
		if err := scanSub(rows, &sub); err != nil {
			continue
		}
		all = append(all, sub)
	}
	if err := rows.Err(); err != nil {
		jsonError(w, "db error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	subs := []map[string]any{}
	for _, sub := range all {
		servers, _ := s.subServers(sub.ID)
		type srvOut struct {
			API    string `json:"api"`
			KeyID  string `json:"key_id"`
			Status string `json:"status"`
			Error  string `json:"error,omitempty"`
		}
		srvList := make([]srvOut, 0, len(servers))
		for _, ss := range servers {
			srvList = append(srvList, srvOut{ss.API, ss.KeyID, ss.Status, ss.Error})
		}
		m := map[string]any{
			"id": sub.ID, "external_id": sub.ExternalID, "name": sub.Name,
			"bytes_limit": sub.BytesLimit, "bytes_used": sub.BytesUsed,
			"expires_at": sub.ExpiresAt, "revoked_at": nullableInt(sub.RevokedAt),
			"servers": srvList,
		}
		if b := s.masterBundle(sub, servers); b != "" {
			m["bundle"] = b
		}
		subs = append(subs, m)
	}
	jsonOK(w, map[string]any{"subscriptions": subs})
}

func nullableInt(v sql.NullInt64) any {
	if v.Valid {
		return v.Int64
	}
	return nil
}

// parsePinHex — строгий hex64 (для join и bundle).
func parsePinHex(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if len(v) != 64 {
		return ""
	}
	for _, c := range v {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return ""
		}
	}
	return v
}
