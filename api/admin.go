package main

import (
	"crypto/subtle"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// ── Admin middleware ───────────────────────────────────────────────────────────

// adminMiddleware проверяет X-Admin-Token для всех /admin/* роутов.
// Порядок: allowlist → блокировка IP (до сверки токена) → сверка токена → учёт неудачи.
// ≥ adminRateLimit неудач за окно с одного IP → 429 даже при верном токене;
// успешные запросы лимит не тратят.
// 2.4: master-token принимается только на узком наборе роутов (masterTokenAllowed);
// неудачный master-token считается тем же лимитером, что и неудачный admin-token.
func (s *Server) adminMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// D2: опциональный allowlist по IP — до проверки токена (пустой список = разрешено всем)
		if !s.adminAllowed(r) {
			jsonError(w, "forbidden", http.StatusForbidden)
			return
		}
		ip := clientIP(r)
		if s.adminAuthLimiter.blocked(ip) {
			w.Header().Set("Retry-After", "60")
			jsonError(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		token := r.Header.Get("X-Admin-Token")
		if !s.tokenAuthorized(token, r.URL.Path) {
			s.adminAuthLimiter.record(ip)
			jsonError(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// tokenAuthorized — единая constant-time сверка токена для adminMiddleware:
// admin-token действует на все /admin/* роуты, master-token (2.4) — только
// на /admin/keys*, /admin/usage и /admin/health.
func (s *Server) tokenAuthorized(token, path string) bool {
	if secretEqual(token, s.cfg.AdminToken) {
		return true
	}
	return s.cfg.MasterToken != "" && masterTokenAllowed(path) && secretEqual(token, s.cfg.MasterToken)
}

// masterTokenAllowed — роуты, доступные с master-token (2.4).
func masterTokenAllowed(path string) bool {
	return path == "/admin/health" || path == "/admin/usage" || strings.HasPrefix(path, "/admin/keys")
}

// secretEqual — constant-time сравнение секрета (пустые значения никогда не равны).
func secretEqual(got, want string) bool {
	if got == "" || want == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// ── Валидация ввода (B3) ─────────────────────────────────────────────────────

const maxExpiresDays = 3650 // ~10 лет; заодно защита от переполнения expires_days*86400

// validateKeyLimits проверяет expires_days / bytes_limit / notes.
// strictExpiry: true (create) — expires_days=0 запрещён, бессрочно только через unlimited:true;
// false (patch) — 0 трактуется как «сделать бессрочным» (обратная совместимость с админкой).
func validateKeyLimits(expiresDays *int64, bytesLimit *int64, notes *string, strictExpiry bool) string {
	if expiresDays != nil {
		if *expiresDays < 0 {
			return "expires_days must be >= 0"
		}
		if *expiresDays > maxExpiresDays {
			return "expires_days too large (max 3650)"
		}
		if strictExpiry && *expiresDays == 0 {
			return "expires_days=0 is not supported: use {\"unlimited\": true} for a perpetual key"
		}
	}
	if bytesLimit != nil && *bytesLimit < 0 {
		return "bytes_limit must be >= 0"
	}
	if notes != nil && len(*notes) > 200 {
		return "notes too long (max 200 characters)"
	}
	return ""
}

// ── POST /admin/keys/create ───────────────────────────────────────────────────

type createKeyRequest struct {
	ExpiresDays int64  `json:"expires_days"` // срок в днях (0 = бессрочно — устаревший вариант, см. unlimited)
	BytesLimit  int64  `json:"bytes_limit"`  // 0 = безлимит (байты)
	LocalLimit  int64  `json:"local_limit"`  // 2.3: локальный стоп на ноде; 0 = нет
	Notes       string `json:"notes"`        // имя юзера / комментарий
	Unlimited   bool   `json:"unlimited"`    // явный бессрочный ключ
	ExternalID  string `json:"external_id"`  // идемпотентность: номер заказа/платежа бота
	// Start (C5): откуда идёт срок. "on_activation" (по умолчанию) — с момента первой
	// активации ключа; "on_create" — с момента создания (прежнее поведение).
	Start string `json:"start"`
}

const (
	startOnActivation = "on_activation"
	startOnCreate     = "on_create"
)

type createKeyResponse struct {
	Key          string `json:"key"`
	ExpiresAt    int64  `json:"expires_at"`      // 0 = бессрочно ИЛИ срок ещё не пошёл (см. duration_days)
	DurationDays int64  `json:"duration_days"`   // >0: срок начнётся с первой активации (C5)
	Start        string `json:"start,omitempty"` // on_activation | on_create (пусто для бессрочных)
	Link         string `json:"link"`            // vkturn://key/<host>/<KEY> — готовая ссылка для пользователя
	Duplicate    bool   `json:"duplicate"`       // true если ключ уже существовал (по external_id)
}

// existingKeyResponse — ответ на повторный create с тем же external_id (C1).
func (s *Server) existingKeyResponse(key string) createKeyResponse {
	var expiresAt, durationDays int64
	_ = s.db.QueryRow(`SELECT expires_at, COALESCE(duration_days, 0) FROM keys WHERE id = ?`, key).
		Scan(&expiresAt, &durationDays)
	resp := createKeyResponse{Key: key, ExpiresAt: expiresAt, DurationDays: durationDays,
		Link: s.buildUserKeyLink(key), Duplicate: true}
	if durationDays > 0 {
		resp.Start = startOnActivation
	}
	return resp
}

func (s *Server) handleAdminCreateKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req createKeyRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	// Идемпотентность (C1): повторный create с тем же external_id возвращает тот же ключ.
	req.ExternalID = strings.TrimSpace(req.ExternalID)
	if req.ExternalID != "" {
		var key string
		err := s.db.QueryRow(`SELECT id FROM keys WHERE external_id = ?`, req.ExternalID).Scan(&key)
		if err == nil {
			jsonOK(w, s.existingKeyResponse(key))
			return
		}
	}

	start := strings.TrimSpace(req.Start)
	if start == "" {
		start = startOnActivation // решение владельца (C5): срок считается с активации
	}
	if start != startOnActivation && start != startOnCreate {
		jsonError(w, `start must be "on_activation" or "on_create"`, http.StatusBadRequest)
		return
	}

	var expDays *int64
	if !req.Unlimited {
		expDays = &req.ExpiresDays
	}
	if msg := validateKeyLimits(expDays, &req.BytesLimit, &req.Notes, true); msg != "" {
		jsonError(w, msg, http.StatusBadRequest)
		return
	}

	if req.LocalLimit < 0 {
		jsonError(w, "local_limit must be >= 0", http.StatusBadRequest)
		return
	}

	key, err := GenerateKey()
	if err != nil {
		jsonError(w, "crypto error", http.StatusInternalServerError)
		return
	}

	now := time.Now().Unix()
	var expiresAt int64
	var durationDays any // NULL, если ключ не ждёт активации
	resp := createKeyResponse{}
	switch {
	case req.Unlimited:
		// бессрочный: expires_at=0, duration_days=NULL
	case start == startOnCreate:
		expiresAt = now + req.ExpiresDays*86400
		resp.Start = startOnCreate
	default: // on_activation: expires_at выставит provisionPort при первой активации
		durationDays = req.ExpiresDays
		resp.DurationDays = req.ExpiresDays
		resp.Start = startOnActivation
	}

	_, err = s.db.Exec(`
		INSERT INTO keys (id, created_at, expires_at, bytes_limit, local_limit, notes, external_id, duration_days)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		key, now, expiresAt, req.BytesLimit, req.LocalLimit, req.Notes, nullIfEmpty(req.ExternalID), durationDays)
	if err != nil {
		// Гонка двух одинаковых external_id: уникальный индекс отдаёт существующий ключ
		if strings.Contains(err.Error(), "UNIQUE") && req.ExternalID != "" {
			var existing string
			if s.db.QueryRow(`SELECT id FROM keys WHERE external_id = ?`, req.ExternalID).Scan(&existing) == nil {
				jsonOK(w, s.existingKeyResponse(existing))
				return
			}
		}
		jsonError(w, "db error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	resp.Key = key
	resp.ExpiresAt = expiresAt
	resp.Link = s.buildUserKeyLink(key)
	jsonOK(w, resp)
}

// buildUserKeyLink (C2) — готовая ссылка vkturn://key/<host>/<KEY>?pin=<TLSPin>.
// Публичный адрес: флаг -public-url / переменная PUBLIC_URL, иначе bind-адрес по факту.
// Пин (S3) добавляется параметром ?pin=, чтобы приложение проверило SPKI-пин сервера
// до отправки ключа (контракт §1). Пин не секрет; если TLSPin пуст (сертификат не
// создан — в норме не бывает после S1), ссылка строится без pin.
func (s *Server) buildUserKeyLink(key string) string {
	host := s.cfg.PublicURL
	if host == "" {
		host = "127.0.0.1:7000" // локальный фоллбэк; на сервере задаётся PUBLIC_URL
	}
	link := "vkturn://key/" + host + "/" + key
	if s.cfg.TLSPin != "" {
		link += "?pin=" + s.cfg.TLSPin
	}
	return link
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// ── GET /admin/keys ───────────────────────────────────────────────────────────

type keyInfo struct {
	ID          string `json:"id"`
	CreatedAt   int64  `json:"created_at"`
	ActivatedAt *int64 `json:"activated_at"`
	ExpiresAt   int64  `json:"expires_at"`
	BytesUsed   int64  `json:"bytes_used"`
	BytesLimit  int64  `json:"bytes_limit"`
	LocalLimit  int64  `json:"local_limit"` // 2.3: локальный стоп на ноде (0 = нет)
	Port        *int   `json:"port"`
	Notes       string `json:"notes"`
	Active      bool   `json:"active"`
	DaysLeft    int64  `json:"days_left"` // -1 = бессрочно
	DeviceBound bool   `json:"device_bound"`
	RevokedAt   *int64 `json:"revoked_at"` // NULL = не отозван (soft-revoke, C6)
	// DurationDays (C5): >0 и expires_at=0 — ключ ждёт активации, срок пойдёт с неё.
	DurationDays int64 `json:"duration_days"`
}

// daysLeftFor считает days_left: -1 = бессрочно; для неактивированного ключа
// с отсчётом «с активации» — весь покупленный срок (C5).
func daysLeftFor(k keyInfo, now int64) int64 {
	if k.ExpiresAt > 0 {
		if now > k.ExpiresAt {
			return 0
		}
		return (k.ExpiresAt - now) / 86400
	}
	if k.ActivatedAt == nil && k.DurationDays > 0 {
		return k.DurationDays
	}
	return -1
}

// keyStatus возвращает вычисляемый статус ключа (для фильтра списка).
func keyStatus(k keyInfo, now int64) string {
	if k.RevokedAt != nil {
		return "revoked"
	}
	if k.ExpiresAt > 0 && now > k.ExpiresAt {
		return "expired"
	}
	if k.BytesLimit > 0 && k.BytesUsed >= k.BytesLimit {
		return "expired"
	}
	if k.Port != nil {
		return "active"
	}
	if k.ActivatedAt != nil {
		return "expired" // активировался, но порт погашен (срок/лимит)
	}
	return "pending"
}

func (s *Server) handleAdminListKeys(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Фильтры (C3): external_id, status, limit, offset
	q := r.URL.Query()
	where, args := []string{"1=1"}, []any{}
	if v := strings.TrimSpace(q.Get("external_id")); v != "" {
		where = append(where, "external_id = ?")
		args = append(args, v)
	}
	limit, offset := 0, 0
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 1000 {
			limit = n
		}
	}
	if v := q.Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = n
		}
	}

	statusFilter := q.Get("status")
	query := `
		SELECT id, created_at, activated_at, expires_at,
		       bytes_used, bytes_limit, COALESCE(local_limit, 0), port, COALESCE(notes, ''), COALESCE(device_id, '') != '', revoked_at,
		       COALESCE(duration_days, 0)
		FROM keys WHERE ` + strings.Join(where, " AND ") + ` ORDER BY created_at DESC`
	// Статус вычисляется в Go, поэтому при фильтре по статусу limit/offset применяем ПОСЛЕ
	// фильтрации (иначе страницы оказываются неполными/пустыми).
	if statusFilter == "" {
		if limit > 0 {
			query += fmt.Sprintf(" LIMIT %d OFFSET %d", limit, offset)
		} else if offset > 0 {
			query += fmt.Sprintf(" LIMIT -1 OFFSET %d", offset)
		}
	}
	rows, err := s.db.Query(query, args...)
	if err != nil {
		jsonError(w, "db error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	now := time.Now().Unix()
	var keys []keyInfo
	for rows.Next() {
		var k keyInfo
		if err := rows.Scan(&k.ID, &k.CreatedAt, &k.ActivatedAt, &k.ExpiresAt,
			&k.BytesUsed, &k.BytesLimit, &k.LocalLimit, &k.Port, &k.Notes, &k.DeviceBound, &k.RevokedAt, &k.DurationDays); err != nil {
			continue
		}
		k.Active = true
		if k.RevokedAt != nil {
			k.Active = false
		}
		if k.ExpiresAt > 0 && now > k.ExpiresAt {
			k.Active = false
		}
		if k.BytesLimit > 0 && k.BytesUsed >= k.BytesLimit {
			k.Active = false
		}
		if k.Port == nil {
			k.Active = false
		}
		k.DaysLeft = daysLeftFor(k, now)
		// Фильтр по статусу вычисляемый — применяется после скана
		if statusFilter != "" && statusFilter != keyStatus(k, now) {
			continue
		}
		keys = append(keys, k)
	}

	if statusFilter != "" {
		if offset >= len(keys) {
			keys = nil
		} else {
			keys = keys[offset:]
			if limit > 0 && limit < len(keys) {
				keys = keys[:limit]
			}
		}
	}

	if keys == nil {
		keys = []keyInfo{}
	}
	jsonOK(w, keys)
}

// ── GET /admin/keys/{id} (C3) ─────────────────────────────────────────────────

func (s *Server) handleAdminGetKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id := keyIDFromPath(r.URL.Path)
	if id == "" {
		jsonError(w, "key id required", http.StatusBadRequest)
		return
	}

	row := s.db.QueryRow(`
		SELECT id, created_at, activated_at, expires_at,
		       bytes_used, bytes_limit, COALESCE(local_limit, 0), port, COALESCE(notes, ''), COALESCE(device_id, '') != '', revoked_at,
		       COALESCE(duration_days, 0)
		FROM keys WHERE id = ?`, id)
	var k keyInfo
	if err := row.Scan(&k.ID, &k.CreatedAt, &k.ActivatedAt, &k.ExpiresAt,
		&k.BytesUsed, &k.BytesLimit, &k.LocalLimit, &k.Port, &k.Notes, &k.DeviceBound, &k.RevokedAt, &k.DurationDays); err != nil {
		jsonError(w, "key not found", http.StatusNotFound)
		return
	}
	now := time.Now().Unix()
	k.Active = keyStatus(k, now) == "active"
	k.DaysLeft = daysLeftFor(k, now)
	jsonOK(w, k)
}

// keyIDFromPath достаёт id из /admin/keys/<id>[/...] и приводит к нижнему регистру (C4).
// Принимает и /v1-алиасы: /v1/admin/keys/<id>.
func keyIDFromPath(path string) string {
	id := strings.TrimPrefix(path, "/v1")
	id = strings.TrimPrefix(id, "/admin/keys/")
	if i := strings.Index(id, "/"); i >= 0 {
		id = id[:i]
	}
	return strings.ToLower(strings.TrimSpace(strings.TrimSuffix(id, "/")))
}

// ── POST /admin/keys/{id}/revoke (C6) ─────────────────────────────────────────

// handleAdminRevokeKey мягко отзывает ключ: порт гасится, активация и /status
// отказывают, но запись остаётся (история продаж). DELETE — полный purge.
func (s *Server) handleAdminRevokeKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id := keyIDFromPath(r.URL.Path)
	if id == "" {
		jsonError(w, "key id required", http.StatusBadRequest)
		return
	}

	var port *int
	var externalID string
	if err := s.db.QueryRow(`SELECT port, IFNULL(external_id,'') FROM keys WHERE id = ?`, id).Scan(&port, &externalID); err != nil {
		jsonError(w, "key not found", http.StatusNotFound)
		return
	}
	if port != nil {
		s.deactivatePort(*port, "admin revoke key "+id)
	}

	// Идемпотентно: повторный revoke не затирает исходный revoked_at.
	now := time.Now().Unix()
	if _, err := s.db.Exec(`UPDATE keys SET revoked_at = COALESCE(revoked_at, ?) WHERE id = ?`, now, id); err != nil {
		jsonError(w, "db error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	var revokedAt int64
	_ = s.db.QueryRow(`SELECT revoked_at FROM keys WHERE id = ?`, id).Scan(&revokedAt)

	jsonOK(w, map[string]any{"status": "revoked", "key": id, "revoked_at": revokedAt})

	// 2.5: ключ отозван — уведомляем продавца.
	s.notifyKeyEvent("key_revoked", id, externalID, 0)
}

// ── DELETE /admin/keys/{id} — purge ───────────────────────────────────────────

func (s *Server) handleAdminDeleteKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id := keyIDFromPath(r.URL.Path)
	if id == "" {
		jsonError(w, "key id required", http.StatusBadRequest)
		return
	}

	// Получаем порт и external_id перед удалением
	row := s.db.QueryRow(`SELECT port, IFNULL(external_id,'') FROM keys WHERE id = ?`, id)
	var port *int
	var externalID string
	_ = row.Scan(&port, &externalID)

	// Деактивируем сервис если был запущен
	if port != nil {
		s.deactivatePort(*port, "admin revoke key "+id)
	}

	// Удаляем ключ из БД
	res, err := s.db.Exec(`DELETE FROM keys WHERE id = ?`, id)
	if err != nil {
		jsonError(w, "db error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		jsonError(w, "key not found", http.StatusNotFound)
		return
	}

	jsonOK(w, map[string]string{"status": "deleted", "key": id})

	// 2.5: purge тоже считается отзывом ключа.
	s.notifyKeyEvent("key_revoked", id, externalID, 0)
}

// ── PATCH /admin/keys/{id} ────────────────────────────────────────────────────

type patchKeyRequest struct {
	ExpiresDays *int64  `json:"expires_days"` // nil = не менять; 0 = бессрочно
	BytesLimit  *int64  `json:"bytes_limit"`  // nil = не менять
	LocalLimit  *int64  `json:"local_limit"`  // nil = не менять; 0 = убрать потолок (2.3)
	Notes       *string `json:"notes"`        // nil = не менять
}

func (s *Server) handleAdminPatchKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPatch {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id := keyIDFromPath(r.URL.Path)
	if id == "" {
		jsonError(w, "key id required", http.StatusBadRequest)
		return
	}

	var req patchKeyRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if msg := validateKeyLimits(req.ExpiresDays, req.BytesLimit, req.Notes, false); msg != "" {
		jsonError(w, msg, http.StatusBadRequest)
		return
	}

	// Получаем текущее состояние
	row := s.db.QueryRow(`SELECT expires_at, bytes_limit, COALESCE(local_limit, 0), notes, activated_at, COALESCE(duration_days, 0)
		FROM keys WHERE id = ?`, id)
	var expiresAt, bytesLimit, localLimit, durationDays int64
	var notes string
	var activatedAt *int64
	if err := row.Scan(&expiresAt, &bytesLimit, &localLimit, &notes, &activatedAt, &durationDays); err != nil {
		jsonError(w, "key not found", http.StatusNotFound)
		return
	}
	prevLimit := bytesLimit

	if req.LocalLimit != nil && *req.LocalLimit < 0 {
		jsonError(w, "local_limit must be >= 0", http.StatusBadRequest)
		return
	}

	// C5: ключ ещё не активирован и срок пойдёт с активации — продление меняет duration_days,
	// expires_at остаётся 0 (отсчёт не запускается).
	pendingStart := activatedAt == nil && durationDays > 0 && expiresAt == 0

	// Применяем изменения
	if req.ExpiresDays != nil {
		switch {
		case pendingStart && *req.ExpiresDays <= 0:
			durationDays = 0 // «сделать бессрочным» — expires_at=0 и нет duration_days
		case pendingStart:
			if durationDays+*req.ExpiresDays > maxExpiresDays {
				jsonError(w, "total duration too large (max 3650 days)", http.StatusBadRequest)
				return
			}
			durationDays += *req.ExpiresDays
		case *req.ExpiresDays <= 0:
			expiresAt = 0 // бессрочно
		default:
			// Продление от текущей даты или от истечения, берём большее
			base := time.Now().Unix()
			if expiresAt > base {
				base = expiresAt
			}
			expiresAt = base + (*req.ExpiresDays)*86400
		}
	}
	if req.BytesLimit != nil {
		bytesLimit = *req.BytesLimit
	}
	if req.LocalLimit != nil {
		localLimit = *req.LocalLimit
	}
	if req.Notes != nil {
		notes = *req.Notes
	}

	_, err := s.db.Exec(`
		UPDATE keys SET expires_at = ?, bytes_limit = ?, local_limit = ?, notes = ?, duration_days = NULLIF(?, 0)
		WHERE id = ?`,
		expiresAt, bytesLimit, localLimit, notes, durationDays, id)
	if err != nil {
		jsonError(w, "db error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Переподъём (A3): ключ активирован, но порт погашен (истёк срок / исчерпан лимит),
	// а теперь продлён или лимит увеличен — выдаём новый порт, user_token сохраняем.
	newPort := 0
	reprovisioned := false
	if (req.ExpiresDays != nil && *req.ExpiresDays > 0) ||
		(req.BytesLimit != nil && bytesLimit > prevLimit) {
		newPort = s.reprovisionIfDowned(id)
		reprovisioned = newPort > 0
	}

	resp := map[string]any{
		"status":        "updated",
		"expires_at":    expiresAt,
		"duration_days": durationDays,
		"bytes_limit":   bytesLimit,
		"local_limit":   localLimit,
		"notes":         notes,
	}
	if reprovisioned {
		resp["new_port"] = newPort
	}
	jsonOK(w, resp)
}

// reprovisionIfDowned поднимает новый порт активированному ключу, чей порт был погашен.
// Возвращает новый порт или 0, если подъём не требовался/не удался.
func (s *Server) reprovisionIfDowned(id string) int {
	var port *int
	var activatedAt *int64
	if err := s.db.QueryRow(`SELECT port, activated_at FROM keys WHERE id = ?`, id).
		Scan(&port, &activatedAt); err != nil {
		return 0
	}
	if port != nil || activatedAt == nil {
		return 0 // порт ещё жив или ключ ни разу не активировался
	}
	var revokedAt *int64
	_ = s.db.QueryRow(`SELECT revoked_at FROM keys WHERE id = ?`, id).Scan(&revokedAt)
	if revokedAt != nil {
		return 0 // отозванный ключ не поднимается продлением/докупкой (C6)
	}
	prov, err := s.provisionPort(id, true)
	if err != nil {
		return 0
	}
	return prov.Port
}

// ── POST /admin/keys/{id}/add_traffic (A4) ───────────────────────────────────

type addTrafficRequest struct {
	Bytes int64 `json:"bytes"` // сколько байт докупить
}

func (s *Server) handleAdminAddTraffic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id := keyIDFromPath(r.URL.Path)
	if id == "" {
		jsonError(w, "key id required", http.StatusBadRequest)
		return
	}

	var req addTrafficRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Bytes <= 0 {
		jsonError(w, "bytes must be > 0", http.StatusBadRequest)
		return
	}

	// Атомарное увеличение лимита; для безлимита (bytes_limit=0) докупать нечего.
	res, err := s.db.Exec(`UPDATE keys SET bytes_limit = bytes_limit + ?
		WHERE id = ? AND bytes_limit > 0`, req.Bytes, id)
	if err != nil {
		jsonError(w, "db error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		var limit int64
		err := s.db.QueryRow(`SELECT bytes_limit FROM keys WHERE id = ?`, id).Scan(&limit)
		if err != nil {
			jsonError(w, "key not found", http.StatusNotFound)
			return
		}
		jsonError(w, "key has no bytes limit (unlimited) — nothing to add", http.StatusBadRequest)
		return
	}

	// Если порт был погашен по лимиту — поднимаем заново (как в A3)
	newPort := s.reprovisionIfDowned(id)
	resp := map[string]any{"status": "updated", "bytes_added": req.Bytes}
	if newPort > 0 {
		resp["new_port"] = newPort
	}
	jsonOK(w, resp)
}

// ── POST /admin/keys/{id}/unbind ───────────────────────────────────────────────────

// handleAdminUnbindKey снимает привязку к устройству и перевыпускает пароль порта:
// все ранее выданные (и разосланные) конфиги перестают работать. Владелец ключа
// активирует его заново той же ссылкой — уже на нужном устройстве.
func (s *Server) handleAdminUnbindKey(w http.ResponseWriter, r *http.Request) {
	id := keyIDFromPath(r.URL.Path)

	var port *int
	var lastUnbind int64
	if err := s.db.QueryRow(`SELECT port, COALESCE(last_unbind_at, 0) FROM keys WHERE id = ?`, id).
		Scan(&port, &lastUnbind); err != nil {
		jsonError(w, "key not found", http.StatusNotFound)
		return
	}

	// Ограничение частоты unbind (G6): по умолчанию раз в 7 дней на ключ.
	if s.cfg.UnbindDays > 0 {
		if next := lastUnbind + int64(s.cfg.UnbindDays)*86400; next > time.Now().Unix() {
			jsonError(w, fmt.Sprintf("unbind allowed once per %d days; try again in %d h",
				s.cfg.UnbindDays, (next-time.Now().Unix()+3599)/3600), http.StatusTooManyRequests)
			return
		}
	}

	newPass, err := randomHex(16)
	if err != nil {
		jsonError(w, "crypto error", http.StatusInternalServerError)
		return
	}
	newToken, err := randomUUID()
	if err != nil {
		jsonError(w, "crypto error", http.StatusInternalServerError)
		return
	}

	if port != nil {
		hy2Pass, _, _, err := s.readMainConfig()
		if err != nil {
			jsonError(w, "server config error: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if err := s.writeUserConf(*port, newPass, hy2Pass); err != nil {
			jsonError(w, "failed to write user config: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	// user_token тоже меняем — старое устройство теряет и доступ к /status
	if _, err := s.db.Exec(`UPDATE keys SET device_id = NULL, wrap_pass = ?, user_token = ?,
		last_unbind_at = ? WHERE id = ?`, newPass, newToken, time.Now().Unix(), id); err != nil {
		jsonError(w, "db error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if port != nil {
		_ = execTimeout(execTimeout10s, "systemctl", "restart", "vkserv@"+strconv.Itoa(*port))
	}
	jsonOK(w, map[string]string{"status": "unbound", "key": id})
}

// ── GET /admin/stats ──────────────────────────────────────────────────────────

type adminStats struct {
	TotalKeys  int   `json:"total_keys"`
	ActiveKeys int   `json:"active_keys"`
	TotalBytes int64 `json:"total_bytes_used"`
	FreePorts  int   `json:"free_ports"`
	UsedPorts  int   `json:"used_ports"`
	// Ёмкость (G3): capacity = max_active, если задан, иначе весь диапазон портов.
	Capacity    int `json:"capacity"`
	ActiveUnits int `json:"active_units"` // живые vkserv@ (для контроля лимита)
}

func (s *Server) handleAdminStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	now := time.Now().Unix()
	var stats adminStats

	_ = s.db.QueryRow(`SELECT COUNT(*) FROM keys`).Scan(&stats.TotalKeys)
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM keys
		WHERE activated_at IS NOT NULL
		  AND port IS NOT NULL
		  AND (expires_at = 0 OR expires_at > ?)
		  AND (bytes_limit = 0 OR bytes_used < bytes_limit)`, now).Scan(&stats.ActiveKeys)
	_ = s.db.QueryRow(`SELECT COALESCE(SUM(bytes_used), 0) FROM keys`).Scan(&stats.TotalBytes)
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM ports WHERE active = 1`).Scan(&stats.UsedPorts)

	portRange := s.cfg.PortEnd - s.cfg.PortStart + 1
	stats.FreePorts = portRange - stats.UsedPorts

	stats.Capacity = s.cfg.MaxActive
	if stats.Capacity == 0 {
		stats.Capacity = portRange
	}
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM keys WHERE port IS NOT NULL AND activated_at IS NOT NULL`).
		Scan(&stats.ActiveUnits)

	jsonOK(w, stats)
}
