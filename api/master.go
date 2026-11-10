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
	"net"
	"net/http"
	"strconv"
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
		M     string `json:"m,omitempty"` // master URL для GET /peek (Android BundleRefresher)
	}
	p := payload{V: 1, N: sub.Name}
	for _, ss := range servers {
		if ss.Status != subActive || ss.KeyID == "" {
			continue
		}
		pin, nodeName := "", ""
		s.db.QueryRow(`SELECT pin, COALESCE(name,'') FROM servers WHERE id = ?`, ss.ServerID).Scan(&pin, &nodeName)
		p.S = append(p.S, srv{API: ss.API, Pin: pin, Key: ss.KeyID, Name: nodeDisplayName(nodeName, ss.API)})
	}
	if len(p.S) == 0 {
		return ""
	}
	if sub.BytesLimit > 0 {
		p.Limit = &sub.BytesLimit
	}
	if s.cfg.PublicURL != "" {
		p.M = s.cfg.PublicURL
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

// nodeDisplayName — имя ноды для поля name в bundle: заданное при join имя,
// иначе хост из api (без схемы и порта). Так клиент различает ноды в группе,
// а не показывает всем одинаковое «VKTurn».
func nodeDisplayName(name, api string) string {
	if n := strings.TrimSpace(name); n != "" && !strings.EqualFold(n, "self") {
		return n
	}
	host := strings.TrimSpace(api)
	if i := strings.Index(host, "://"); i >= 0 {
		host = host[i+3:]
	}
	if i := strings.IndexAny(host, "/?#"); i >= 0 {
		host = host[:i]
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return host
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

// handleMasterPeek — GET /v1/peek
// Публичный (только user_token), режим мастера.
// Возвращает свежий bundle подписки, к которой привязан токен.
// Клиент вызывает при старте: если bundle изменился (ноды добавлены/удалены) —
// переактивирует группу и обновляет список серверов.
// Подписка находится по локальному ключу (self-доставка): при раскатке на мастер
// как ноду ключ создаётся и в локальной таблице keys с user_token.
func (s *Server) handleMasterPeek(w http.ResponseWriter, r *http.Request) {
	if !s.requireMaster(w) { return }
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	token := bearerToken(r)
	if token == "" {
		jsonError(w, "authorization required", http.StatusUnauthorized)
		return
	}
	// Находим подписку по user_token локального ключа (self-доставка подписки)
	var subID int64
	err := s.db.QueryRow(`
		SELECT ss.sub_id
		FROM subscription_servers ss
		JOIN keys k ON k.id = ss.key_id
		WHERE k.user_token = ?
		LIMIT 1`, token).Scan(&subID)
	if err != nil {
		jsonError(w, "subscription not found", http.StatusNotFound)
		return
	}
	resp := s.subscriptionResponse(subID, 0)
	bundle, _ := resp["bundle"].(string)
	if bundle == "" {
		jsonError(w, "bundle not available", http.StatusServiceUnavailable)
		return
	}
	jsonOK(w, map[string]any{
		"bundle": bundle,
		"sub_id": subID,
	})
}

// ── DELETE /master/servers/{id} ─────────────────────────────────────────────────

// handleMasterDeleteServer удаляет ноду из реестра мастера.
// Best-effort: пытается удалить ключи всех подписок на этой ноде (если она доступна),
// затем убирает запись сервера и все subscription_servers для него.
// Если нода недоступна — ключи на ней останутся, но мастер про неё забудет.
// Авторизация — X-Master-Token (masterTokenMiddleware): удаление ноды недоступно
// админ-токену продавца.
func (s *Server) handleMasterDeleteServer(w http.ResponseWriter, r *http.Request) {
	if !s.requireMaster(w) {
		return
	}
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// id — последний сегмент пути (/master/servers/{id})
	p := strings.TrimPrefix(r.URL.Path, "/v1")
	p = strings.TrimPrefix(p, "/master/servers/")
	p = strings.TrimSuffix(p, "/")
	nodeID, err := strconv.ParseInt(p, 10, 64)
	if err != nil || nodeID <= 0 {
		jsonError(w, "server id required", http.StatusBadRequest)
		return
	}

	var node nodeRow
	node, err = scanNode(s.db.QueryRow(`SELECT `+nodeCols+` FROM servers WHERE id = ?`, nodeID))
	if err != nil {
		jsonError(w, "server not found", http.StatusNotFound)
		return
	}

	// Собираем ключи подписок на этой ноде
	type subKey struct{ keyID string }
	rows, _ := s.db.Query(`SELECT key_id FROM subscription_servers WHERE server_id = ? AND key_id != ''`, nodeID)
	var keys []string
	if rows != nil {
		for rows.Next() {
			var k string
			rows.Scan(&k)
			keys = append(keys, k)
		}
		rows.Close()
	}

	// Best-effort: удаляем ключи на ноде если она доступна
	deleted := 0
	if node.Status == "active" {
		for _, keyID := range keys {
			if err := s.nodeCall(node, http.MethodDelete, "/v1/admin/keys/"+keyID, nil, nil); err == nil {
				deleted++
			}
		}
	}

	// Удаляем записи доставки и саму ноду
	s.db.Exec(`DELETE FROM subscription_servers WHERE server_id = ?`, nodeID)
	if _, err := s.db.Exec(`DELETE FROM servers WHERE id = ?`, nodeID); err != nil {
		jsonError(w, "db error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	log.Printf("[master] нода %d (%s) удалена из реестра, ключей удалено %d/%d", nodeID, node.API, deleted, len(keys))
	jsonOK(w, map[string]any{
		"status":       "deleted",
		"server_id":    nodeID,
		"keys_deleted": deleted,
		"keys_total":   len(keys),
	})
}

// ── DELETE /master/subscriptions/{id} ──────────────────────────────────────────

// handleMasterDeleteSub удаляет подписку вместе с её ключами на всех нодах:
// порт гасится, ключи и запись удаляются — подключение по этим ключам перестаёт
// работать сразу. Нода, недоступная в момент удаления, получает status=failed
// в ответе; её ключ удаляется вручную или при повторном вызове не понадобится —
// запись подписки всё равно удаляется.
func (s *Server) handleMasterDeleteSub(w http.ResponseWriter, r *http.Request) {
	if !s.requireMaster(w) {
		return
	}
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// id — сегмент пути /master/subscriptions/{id} (с /v1 или без)
	id, ok := subIDFromSubPath(w, r, "")
	if !ok {
		return
	}

	var sub subRow
	if err := scanSub(s.db.QueryRow(`SELECT `+subCols+` FROM subscriptions WHERE id = ?`, id), &sub); err != nil {
		jsonError(w, "subscription not found", http.StatusNotFound)
		return
	}

	servers, _ := s.subServers(id)
	nodes, _ := s.listNodes()
	byID := make(map[int64]nodeRow, len(nodes))
	for _, n := range nodes {
		byID[n.ID] = n
	}

	type delRes struct {
		API    string `json:"api"`
		KeyID  string `json:"key_id"`
		Status string `json:"status"` // deleted | failed | skipped
		Error  string `json:"error,omitempty"`
	}
	results := make([]delRes, 0, len(servers))
	deleted := 0
	for _, ss := range servers {
		res := delRes{API: ss.API, KeyID: ss.KeyID, Status: "skipped"}
		if ss.KeyID != "" {
			if n, ok := byID[ss.ServerID]; ok && n.Status == "active" {
				if err := s.nodeCall(n, http.MethodDelete, "/v1/admin/keys/"+ss.KeyID, nil, nil); err != nil {
					res.Status, res.Error = "failed", err.Error()
				} else {
					res.Status = "deleted"
					deleted++
				}
			} else {
				res.Status, res.Error = "failed", "нода недоступна"
			}
		}
		results = append(results, res)
	}

	// Локальные хвосты: ключи мастера с этим external_id (вдруг self-call не прошёл),
	// записи о доставке и сама подписка.
	s.db.Exec(`DELETE FROM keys WHERE external_id = ?`, sub.ExternalID)
	s.db.Exec(`DELETE FROM subscription_servers WHERE sub_id = ?`, id)
	if _, err := s.db.Exec(`DELETE FROM subscriptions WHERE id = ?`, id); err != nil {
		jsonError(w, "db error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	log.Printf("[master] подписка %d (%s) удалена: ключей удалено %d/%d", id, sub.ExternalID, deleted, len(results))
	jsonOK(w, map[string]any{"status": "deleted", "id": id, "deleted": deleted, "servers": results})
}

// ── Жизненный цикл подписки: продление, докупка, отзыв, unbind ─────────────────
// Срок и лимиты подписки живут в ключах на нодах (в subscriptions нет колонок
// duration/expires — см. restoreExpiresDays): операции — fan-out на доставленные
// ключи через nodeCall. Статусы доставки при сбое операции НЕ меняются: ключ
// существует, сбой — ошибка вызова, она честно возвращается в results.

// subOpResult — исход операции на одной ноде.
type subOpResult struct {
	API    string `json:"api"`
	KeyID  string `json:"key_id"`
	Status string `json:"status"` // ok | failed | skipped
	Error  string `json:"error,omitempty"`
}

// fanoutSubOp применяет op к каждой доставке подписки со статусом active:
// pending/failed (ключа ещё нет) и недоступные ноды пропускаются.
// Возвращает results и число успешных нод.
func (s *Server) fanoutSubOp(subID int64, op func(n nodeRow, ss subServerRow) error) ([]subOpResult, int) {
	servers, _ := s.subServers(subID)
	nodes, _ := s.listNodes()
	byID := make(map[int64]nodeRow, len(nodes))
	for _, n := range nodes {
		byID[n.ID] = n
	}
	results := make([]subOpResult, 0, len(servers))
	okN := 0
	for _, ss := range servers {
		res := subOpResult{API: ss.API, KeyID: ss.KeyID, Status: "skipped"}
		if ss.Status == subActive && ss.KeyID != "" {
			if n, found := byID[ss.ServerID]; found && n.Status == "active" {
				if err := op(n, ss); err != nil {
					res.Status, res.Error = "failed", err.Error()
				} else {
					res.Status = "ok"
					okN++
				}
			} else {
				res.Status, res.Error = "failed", "нода недоступна"
			}
		}
		results = append(results, res)
	}
	return results, okN
}

// subIDFromSubPath — числовой id подписки из пути
// /master/subscriptions/{id}[/action] (с /v1 или без). При ошибке уже записал 400.
func subIDFromSubPath(w http.ResponseWriter, r *http.Request, action string) (int64, bool) {
	p := strings.TrimPrefix(r.URL.Path, "/v1")
	p = strings.TrimPrefix(p, "/master/subscriptions/")
	p = strings.TrimSuffix(p, "/")
	if action != "" {
		p = strings.TrimSuffix(p, "/"+action)
	}
	id, err := strconv.ParseInt(p, 10, 64)
	if err != nil || id <= 0 {
		jsonError(w, "subscription id required", http.StatusBadRequest)
		return 0, false
	}
	return id, true
}

// subForOp — загрузить подписку или ответить 404. false = ответ уже отправлен.
func (s *Server) subForOp(w http.ResponseWriter, id int64) (subRow, bool) {
	var sub subRow
	if err := scanSub(s.db.QueryRow(`SELECT `+subCols+` FROM subscriptions WHERE id = ?`, id), &sub); err != nil {
		jsonError(w, "subscription not found", http.StatusNotFound)
		return subRow{}, false
	}
	return sub, true
}

// handleMasterPatchSub — PATCH /master/subscriptions/{id}: продление подписки.
// expires_days добавляются к сроку каждого доставленного ключа (семантика PATCH
// ключа: активированный — от конца срока или от сегодня, если истёк; ожидающий
// активации — к duration_days). Досыл отложенных нод (resendPending) читает срок
// с активной доставки — продление унаследуется автоматически.
func (s *Server) handleMasterPatchSub(w http.ResponseWriter, r *http.Request) {
	if !s.requireMaster(w) {
		return
	}
	if r.Method != http.MethodPatch {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id, ok := subIDFromSubPath(w, r, "")
	if !ok {
		return
	}
	if _, found := s.subForOp(w, id); !found {
		return
	}
	var req struct {
		ExpiresDays int64 `json:"expires_days"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.ExpiresDays <= 0 || req.ExpiresDays > maxExpiresDays {
		jsonError(w, "expires_days must be between 1 and 3650", http.StatusBadRequest)
		return
	}
	body := map[string]any{"expires_days": req.ExpiresDays}
	results, okN := s.fanoutSubOp(id, func(n nodeRow, ss subServerRow) error {
		return s.nodeCall(n, http.MethodPatch, "/v1/admin/keys/"+ss.KeyID, body, nil)
	})
	log.Printf("[master] подписка %d: продление +%d д, нод ok %d/%d", id, req.ExpiresDays, okN, len(results))
	resp := s.subscriptionResponse(id, okN)
	resp["status"] = "updated"
	resp["expires_days_added"] = req.ExpiresDays
	resp["results"] = results
	jsonOK(w, resp)
}

// handleMasterAddTrafficSub — POST /master/subscriptions/{id}/add_traffic.
// Прибавляет bytes к bytes_limit подписки и выставляет новый общий лимит
// (bytes_limit + local_limit) ключам на всех доставленных нодах — нода сама
// переподнимет погашенный по лимиту порт (reprovisionIfDowned).
func (s *Server) handleMasterAddTrafficSub(w http.ResponseWriter, r *http.Request) {
	if !s.requireMaster(w) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id, ok := subIDFromSubPath(w, r, "add_traffic")
	if !ok {
		return
	}
	sub, found := s.subForOp(w, id)
	if !found {
		return
	}
	var req struct {
		Bytes int64 `json:"bytes"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Bytes <= 0 {
		jsonError(w, "bytes must be > 0", http.StatusBadRequest)
		return
	}
	if sub.BytesLimit == 0 {
		jsonError(w, "subscription has no bytes limit (unlimited) — nothing to add", http.StatusBadRequest)
		return
	}
	newLimit := sub.BytesLimit + req.Bytes
	if newLimit <= sub.BytesLimit { // переполнение int64
		jsonError(w, "bytes_limit overflow", http.StatusBadRequest)
		return
	}
	if _, err := s.db.Exec(`UPDATE subscriptions SET bytes_limit = ? WHERE id = ?`, newLimit, id); err != nil {
		jsonError(w, "db error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	body := map[string]any{"bytes_limit": newLimit, "local_limit": newLimit}
	results, okN := s.fanoutSubOp(id, func(n nodeRow, ss subServerRow) error {
		return s.nodeCall(n, http.MethodPatch, "/v1/admin/keys/"+ss.KeyID, body, nil)
	})
	log.Printf("[master] подписка %d: +%d байт (лимит %d), нод ok %d/%d", id, req.Bytes, newLimit, okN, len(results))
	resp := s.subscriptionResponse(id, okN)
	resp["status"] = "updated"
	resp["bytes_added"] = req.Bytes
	resp["bytes_limit"] = newLimit
	resp["results"] = results
	jsonOK(w, resp)
}

// handleMasterRevokeSub — POST /master/subscriptions/{id}/revoke: отзыв подписки.
// Гасит ключи на всех доставленных нодах и ставит revoked_at (идемпотентно:
// повторный вызов не трогает ноды и возвращает текущее состояние).
func (s *Server) handleMasterRevokeSub(w http.ResponseWriter, r *http.Request) {
	if !s.requireMaster(w) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id, ok := subIDFromSubPath(w, r, "revoke")
	if !ok {
		return
	}
	sub, found := s.subForOp(w, id)
	if !found {
		return
	}
	if sub.RevokedAt.Valid {
		resp := s.subscriptionResponse(id, 0)
		resp["status"] = "revoked"
		resp["already_revoked"] = true
		jsonOK(w, resp)
		return
	}
	now := time.Now().Unix()
	if _, err := s.db.Exec(`UPDATE subscriptions SET revoked_at = COALESCE(revoked_at, ?) WHERE id = ?`, now, id); err != nil {
		jsonError(w, "db error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	results, okN := s.fanoutSubOp(id, func(n nodeRow, ss subServerRow) error {
		return s.nodeCall(n, http.MethodPost, "/v1/admin/keys/"+ss.KeyID+"/revoke", nil, nil)
	})
	log.Printf("[master] подписка %d (%s) отозвана: нод ok %d/%d", id, sub.ExternalID, okN, len(results))
	resp := s.subscriptionResponse(id, okN)
	resp["status"] = "revoked"
	resp["revoked_at"] = now
	resp["results"] = results
	jsonOK(w, resp)
}

// handleMasterUnbindSub — POST /master/subscriptions/{id}/unbind: смена
// устройства для всей подписки. Нодовый 7-дневный лимит (cfg.UnbindDays)
// проверяется каждой нодой отдельно: часть нод может ответить 429 — это failed
// в results, остальные отрабатывают.
func (s *Server) handleMasterUnbindSub(w http.ResponseWriter, r *http.Request) {
	if !s.requireMaster(w) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id, ok := subIDFromSubPath(w, r, "unbind")
	if !ok {
		return
	}
	if _, found := s.subForOp(w, id); !found {
		return
	}
	results, okN := s.fanoutSubOp(id, func(n nodeRow, ss subServerRow) error {
		return s.nodeCall(n, http.MethodPost, "/v1/admin/keys/"+ss.KeyID+"/unbind", nil, nil)
	})
	log.Printf("[master] подписка %d: unbind, нод ok %d/%d", id, okN, len(results))
	resp := s.subscriptionResponse(id, okN)
	resp["status"] = "unbound"
	resp["results"] = results
	jsonOK(w, resp)
}
