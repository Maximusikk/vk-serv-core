package main

// Этап 3.4/3.5: фоновые циклы мастера — досыл недоставленных ключей (30 с),
// сбор usage с нод и гашение лимита/срока (60 с), health-проба нод (30 с).
//
// Циклы ходят к нодам тем же pinned-клиентом (master_client.go), что и ручная
// раскатка: подмена транспорта невозможна, ошибки nodeCall не двигают курсоры.

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

const (
	resendInterval = 30 * time.Second
	trafficPeriod  = 60 * time.Second
	healthInterval = 30 * time.Second
	usagePageSize  = 1000
)

// runMasterCycles — три тикера мастера. В не-master режиме ничего не делает.
// Каждый тик закрыт recover: сбой одного тика не убивает горутину.
func (s *Server) runMasterCycles(ctx context.Context) {
	if s.cfg.Mode != masterMode {
		return
	}
	resendT := time.NewTicker(resendInterval)
	defer resendT.Stop()
	trafficT := time.NewTicker(trafficPeriod)
	defer trafficT.Stop()
	healthT := time.NewTicker(healthInterval)
	defer healthT.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-resendT.C:
			s.safeTick("resend", s.resendTick)
		case <-trafficT.C:
			s.safeTick("traffic", s.trafficTick)
		case <-healthT.C:
			s.safeTick("health", s.healthTick)
		}
	}
}

func (s *Server) safeTick(name string, fn func()) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[master:%s] паника (восстановлено): %v", name, r)
		}
	}()
	fn()
}

// ── досыл (3.4) ──────────────────────────────────────────────────────────────────

// resendTick ищет подписки, у которых на активных нодах остались pending/failed,
// и досылает ключ ТОЛЬКО им (активные доставки не трогаются — на ноде уже есть
// ключ, повторный create создал бы дубль).
//
// Про expires_days при досыле: колонки в subscriptions нет (схему db.go менять
// нельзя), исходный expires_days известен только в момент создания. Решение:
// срок восстанавливается по любому УЖЕ доставленному (active) серверу —
// GET /v1/admin/keys/<key_id> → expires_at, и expires_days = округлённый вверх
// остаток (expires_at - now)/86400, минимум 1 (нода сама пересчитает expires_at
// при активации ключа). Если ни одной active доставки нет (например, все ноды
// упали сразу после создания подписки) — досыл откладывается до следующего
// тика: pending-статусы остаются, ничего не ломается.
func (s *Server) resendTick() {
	// Подписки, где есть недоставленное на активной ноде И есть хоть одна
	// активная доставка (иначе expires_days восстановить не из чего).
	rows, err := s.db.Query(`
		SELECT DISTINCT ss.sub_id
		FROM subscription_servers ss JOIN servers sv ON sv.id = ss.server_id
		WHERE sv.status = 'active' AND ss.status IN (?, ?)
		  AND EXISTS (
			SELECT 1 FROM subscription_servers a JOIN servers s2 ON s2.id = a.server_id
			WHERE a.sub_id = ss.sub_id AND a.status = ? AND s2.status = 'active'
			  AND a.key_id <> '')`, subPending, subFailed, subActive)
	if err != nil {
		log.Printf("[master:resend] выборка подписок: %v", err)
		return
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err == nil {
			ids = append(ids, id)
		}
	}
	rows.Close()
	for _, id := range ids {
		s.resendPending(id)
	}
}

// resendPending досылает ключ одной подписки недоставленным нодам.
func (s *Server) resendPending(subID int64) {
	var sub subRow
	if err := scanSub(s.db.QueryRow(`SELECT `+subCols+` FROM subscriptions WHERE id = ?`, subID), &sub); err != nil {
		log.Printf("[master:resend] подписка %d: %v", subID, err)
		return
	}
	if sub.RevokedAt.Valid {
		return // отозванная — досылать нечего
	}

	days, ok := s.restoreExpiresDays(sub)
	if !ok {
		return // отложено до следующего тика
	}

	// Недоставленные строки на активных нодах.
	type target struct {
		node nodeRow
		ss   subServerRow
	}
	var targets []target
	for _, ss := range s.mustSubServers(subID) {
		if ss.Status == subActive || ss.KeyID != "" {
			continue
		}
		n, err := s.nodeByID(ss.ServerID)
		if err != nil || n.Status != "active" {
			continue
		}
		targets = append(targets, target{n, ss})
	}
	for _, t := range targets {
		var resp struct {
			Key string `json:"key"`
		}
		err := s.nodeCall(t.node, http.MethodPost, "/v1/admin/keys/create", map[string]any{
			"expires_days": days,
			"start":        "on_activation",
			"bytes_limit":  sub.BytesLimit,
			"local_limit":  sub.BytesLimit,
			"external_id":  sub.ExternalID,
		}, &resp)
		var st, keyID, errText string
		switch {
		case err == nil && resp.Key != "":
			st, keyID = subActive, resp.Key
			log.Printf("[master:resend] подписка %d: ключ доставлен на %s", subID, t.node.API)
		case err == nil:
			st, errText = subFailed, "нода вернула пустой key"
		default:
			st, errText = subFailed, err.Error()
		}
		if _, err := s.db.Exec(`
			UPDATE subscription_servers SET key_id = ?, status = ?, error = ?
			WHERE sub_id = ? AND server_id = ?`,
			keyID, st, errText, subID, t.node.ID); err != nil {
			log.Printf("[master:resend] подписка %d: статус ноды %s: %v", subID, t.node.API, err)
		}
	}
}

// restoreExpiresDays восстанавливает срок подписки по active-доставке (см.
// комментарий resendTick). ok=false — восстановить не удалось, досыл отложен.
func (s *Server) restoreExpiresDays(sub subRow) (int64, bool) {
	for _, ss := range s.mustSubServers(sub.ID) {
		if ss.Status != subActive || ss.KeyID == "" {
			continue
		}
		var key struct {
			ExpiresAt int64 `json:"expires_at"`
		}
		n, err := s.nodeByID(ss.ServerID)
		if err != nil || n.Status != "active" {
			continue
		}
		if err := s.nodeCall(n, http.MethodGet, "/v1/admin/keys/"+ss.KeyID, nil, &key); err != nil {
			log.Printf("[master:resend] подписка %d: срок ноды %s: %v", sub.ID, n.API, err)
			continue
		}
		if key.ExpiresAt <= 0 {
			continue // ключ ещё не активирован (on_activation) — срока нет
		}
		remaining := key.ExpiresAt - time.Now().Unix()
		if remaining < 86400 {
			remaining = 86400
		}
		return (remaining + 86399) / 86400, true // ceil, минимум 1 день
	}
	return 0, false
}

// nodeByID — нода по id (subServers отдаёт server_id, для nodeCall нужна строка).
func (s *Server) nodeByID(id int64) (nodeRow, error) {
	return scanNode(s.db.QueryRow(`SELECT `+nodeCols+` FROM servers WHERE id = ?`, id))
}

// mustSubServers — subServers без ретрая: ошибка чтения логируется, пусто.
func (s *Server) mustSubServers(subID int64) []subServerRow {
	ss, err := s.subServers(subID)
	if err != nil {
		log.Printf("[master] подписка %d: ноды: %v", subID, err)
		return nil
	}
	return ss
}

// ── трафик (3.4) ─────────────────────────────────────────────────────────────────

// trafficTick собирает usage с каждой ноды курсором servers.since. Курсор
// двигается только после ПОЛНОГО успешного забора ноды; при сбое нода доберёт
// то же окно на следующем тике (usage_log на ноде — источник, дубликатов нет).
func (s *Server) trafficTick() {
	nodes, err := s.listNodes()
	if err != nil {
		log.Printf("[master:traffic] ноды: %v", err)
		return
	}
	for _, n := range nodes {
		s.collectNodeUsage(n)
	}
	s.enforceLimits()
}

type usageItemResp struct {
	KeyID      string `json:"key_id"`
	ExternalID string `json:"external_id"`
	Bytes      int64  `json:"bytes"`
}

// collectNodeUsage вычитывает все страницы usage ноды и прибавляет дельты к
// subscriptions.bytes_used. Курсор ноды двигается только при полном успехе.
func (s *Server) collectNodeUsage(n nodeRow) {
	cursor := n.Since
	for page := 0; ; page++ {
		var resp struct {
			Items []usageItemResp `json:"items"`
			Next  int64           `json:"next"`
		}
		path := fmt.Sprintf("/v1/admin/usage?since=%d&limit=%d", cursor, usagePageSize)
		if err := s.nodeCall(n, http.MethodGet, path, nil, &resp); err != nil {
			// Курсор не двигаем: недочитанное окно доберётся следующим тиком.
			log.Printf("[master:traffic] нода %s: %v", n.API, err)
			return
		}
		for _, it := range resp.Items {
			if it.KeyID == "" || it.Bytes == 0 {
				continue
			}
			if _, err := s.db.Exec(`
				UPDATE subscriptions SET bytes_used = bytes_used + ?
				WHERE id = (SELECT sub_id FROM subscription_servers WHERE key_id = ?)`,
				it.Bytes, it.KeyID); err != nil {
				log.Printf("[master:traffic] дельта key %s: %v", it.KeyID, err)
				return // счётчик недостоверен — курсор не двигаем
			}
		}
		if resp.Next > cursor {
			cursor = resp.Next
		}
		if len(resp.Items) < usagePageSize {
			break // страница неполная — вычитали всё
		}
		if page > 1000 { // страховка от бесконечного цикла
			log.Printf("[master:traffic] нода %s: слишком много страниц, курсор на %d", n.API, cursor)
			break
		}
	}
	if cursor != n.Since {
		if _, err := s.db.Exec(`UPDATE servers SET since = ? WHERE id = ?`, cursor, n.ID); err != nil {
			log.Printf("[master:traffic] курсор ноды %s: %v", n.API, err)
		}
	}
}

// enforceLimits гасит подписки, вышедшие за лимит трафика или срок, — revoke
// ключа на всех нодах, где ключ создавался, и revoked_at в БД мастера.
func (s *Server) enforceLimits() {
	now := time.Now().Unix()
	rows, err := s.db.Query(`SELECT ` + subCols + ` FROM subscriptions
		WHERE revoked_at IS NULL
		  AND ((bytes_limit > 0 AND bytes_used >= bytes_limit) OR (expires_at > 0 AND expires_at < ?))`, now)
	if err != nil {
		log.Printf("[master:traffic] лимиты: %v", err)
		return
	}
	defer rows.Close()
	var toRevoke []subRow
	for rows.Next() {
		var sub subRow
		if err := scanSub(rows, &sub); err == nil {
			toRevoke = append(toRevoke, sub)
		}
	}
	rows.Close()
	for _, sub := range toRevoke {
		reason := "traffic limit"
		if sub.ExpiresAt > 0 && sub.ExpiresAt < now {
			reason = "expired"
		}
		log.Printf("[master:traffic] подписка %d (%s): %s, отзыв ключей", sub.ID, sub.ExternalID, reason)
		for _, ss := range s.mustSubServers(sub.ID) {
			if ss.KeyID == "" {
				continue
			}
			n, err := s.nodeByID(ss.ServerID)
			if err != nil {
				continue
			}
			if err := s.nodeCall(n, http.MethodPost, "/v1/admin/keys/"+ss.KeyID+"/revoke", nil, nil); err != nil {
				log.Printf("[master:traffic] revoke %s на %s: %v", ss.KeyID, n.API, err)
			}
		}
		if _, err := s.db.Exec(`UPDATE subscriptions SET revoked_at = ? WHERE id = ?`, now, sub.ID); err != nil {
			log.Printf("[master:traffic] revoked_at подписки %d: %v", sub.ID, err)
		}
	}
}

// ── health (3.4) ─────────────────────────────────────────────────────────────────

// healthTick пробует /v1/admin/health каждой ноды: успех — active + last_seen,
// любая ошибка nodeCall (включая pin mismatch) — down. На переходах active↔down
// шлётся вебхук node_up/node_down продавцу (если NotifyURL задан).
func (s *Server) healthTick() {
	nodes, err := s.listNodes()
	if err != nil {
		log.Printf("[master:health] ноды: %v", err)
		return
	}
	for _, n := range nodes {
		var h struct {
			Status string `json:"status"`
		}
		err := s.nodeCall(n, http.MethodGet, "/v1/admin/health", nil, &h)
		now := time.Now().Unix()
		if err == nil {
			s.db.Exec(`UPDATE servers SET status = 'active', last_seen = ? WHERE id = ?`, now, n.ID)
		} else {
			s.db.Exec(`UPDATE servers SET status = 'down' WHERE id = ?`, n.ID)
		}
		if n.Status == "active" && err != nil {
			s.sendNodeWebhook("node_down", n.API, err.Error())
		} else if n.Status == "down" && err == nil {
			s.sendNodeWebhook("node_up", n.API, "")
		}
	}
}

// nodeEventPayload — тело вебхука о состоянии ноды (локальная структура: notify.go
// не трогаем; формат полей тот же, что у остальных вебхуков).
type nodeEventPayload struct {
	Type    string `json:"type"` // node_down | node_up
	API     string `json:"api"`
	Message string `json:"message"`
	TS      int64  `json:"ts"`
	Version string `json:"api_version"`
}

// sendNodeWebhook — POST на NotifyURL тем же способом, что sendPortDownWebhook:
// go-рутина, клиент с таймаутом 10 с. Молчит, если NotifyURL не задан.
func (s *Server) sendNodeWebhook(event, api, msg string) {
	if s.cfg.NotifyURL == "" {
		return
	}
	p := nodeEventPayload{Type: event, API: api, Message: msg, TS: time.Now().Unix(), Version: APIVersion}
	go func() {
		defer func() { _ = recover() }()
		body, err := json.Marshal(p)
		if err != nil {
			return
		}
		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Post(s.cfg.NotifyURL, "application/json", strings.NewReader(string(body)))
		if err != nil {
			log.Printf("[master:health] %s: %v", event, err)
			return
		}
		resp.Body.Close()
		if resp.StatusCode >= 300 {
			log.Printf("[master:health] %s: HTTP %d", event, resp.StatusCode)
			return
		}
		log.Printf("[master:health] вебхук отправлен: %s (%s)", event, api)
	}()
}

// ── саморегистрация (3.5) ────────────────────────────────────────────────────────

// registerSelfNode регистрирует мастера как собственную ноду (-also-node):
// та же таблица servers, те же циклы. HTTP-вызов к себе при регистрации не
// делается — upsertNode достаточно; циклы (usage/health) ходят к себе по
// публичному адресу через nodeCall как к обычной ноде: если адрес резолвится
// снаружи, но недоступен изнутри, нода «self» будет показана как down — это
// допустимое состояние, на работу остальных нод не влияет.
func (s *Server) registerSelfNode() error {
	api := s.cfg.PublicURL
	if api == "" {
		// PublicURL пуст: пробуем bind+port, но 0.0.0.0/:: наружу не адрес.
		ip := net.ParseIP(s.cfg.BindAddr)
		if ip == nil || ip.IsUnspecified() {
			return fmt.Errorf("registerSelfNode: не знаю публичный адрес мастера — задай PUBLIC_URL (напр. example.com:7000)")
		}
		api = net.JoinHostPort(s.cfg.BindAddr, s.cfg.ListenPort)
	}
	if s.cfg.MasterToken == "" {
		return fmt.Errorf("registerSelfNode: ноде нужен master-token — задай MASTER_TOKEN")
	}
	capacity := int64(s.cfg.MaxActive)
	if capacity <= 0 {
		capacity = int64(s.cfg.PortEnd - s.cfg.PortStart + 1)
	}
	id, err := s.upsertNode(nodeRow{
		API:         api,
		Pin:         s.cfg.TLSPin, // пин собственного сертификата; пустой пин = нода self будет down (dialPinned запрещает)
		MasterToken: s.cfg.MasterToken,
		Name:        "self",
		Version:     APIVersion,
		Capacity:    capacity,
	})
	if err != nil {
		return fmt.Errorf("registerSelfNode: %w", err)
	}
	log.Printf("[master] нода self зарегистрирована: %s (id=%d, capacity=%d)", api, id, capacity)
	return nil
}
