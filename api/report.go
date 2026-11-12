package main

// Отчёты об ошибках из пользовательского приложения.
//
//   POST   /report                  — приложение шлёт лог + описание (Bearer user_token)
//   GET    /admin/reports           — список (X-Admin-Token): ?key=&code=&limit=&before=
//   GET    /admin/reports/{code}    — один отчёт целиком (с логом)
//   DELETE /admin/reports/{code}    — удалить
//
// Защита сервера от забивания:
//   - только владелец активированного ключа (токен) — анонимных отчётов нет;
//   - не чаще одного отчёта в reportRateWin на КЛЮЧ (не на IP: из туннеля у всех пользователей IP один — IP VPS);
//   - тело запроса не больше reportMaxBody (http.MaxBytesReader считает фактические байты,
//     а не заголовок Content-Length), поля обрезаются до своих лимитов, лог — до reportMaxLog;
//   - на ключ хранится не больше reportKeepPerKey последних отчётов, всего — не больше reportKeepTotal,
//     записи старше reportRetention чистятся фоново (см. runTrafficPoller);
//   - содержимое лога — только текст: админка обязана выводить его как текст, не как HTML.

import (
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	reportMaxBody    = 1 << 20           // потолок тела запроса, байт
	reportMaxLog     = 256 << 10         // лог после обрезки (остаётся хвост — он важнее), байт
	reportMaxComment = 1000              // комментарий пользователя, байт
	reportRateWin    = 5 * time.Minute   // один отчёт на ключ за окно
	reportRetention  = 30 * 24 * time.Hour
	reportKeepPerKey = 20
	reportKeepTotal  = 2000

	reportCodeAlphabet = "23456789ABCDEFGHJKMNPQRSTUVWXYZ" // без 0/O/1/I/L: код диктуют голосом
	reportCodeLen      = 6
)

type reportRequest struct {
	AppVersion string `json:"app_version"`
	Device     string `json:"device"`
	Android    string `json:"android"`
	Transport  string `json:"transport"`
	LastError  string `json:"last_error"`
	Comment    string `json:"comment"`
	Log        string `json:"log"`
}

// clampText убирает NUL и битый UTF-8 и обрезает строку до max байт (с головы).
func clampText(s string, max int) string {
	s = strings.ToValidUTF8(s, "?")
	s = strings.ReplaceAll(s, "\x00", "")
	if len(s) > max {
		s = strings.ToValidUTF8(s[:max], "")
	}
	return s
}

// clampTail обрезает строку до max байт, оставляя ХВОСТ (в логе важны последние события).
func clampTail(s string, max int) string {
	s = strings.ToValidUTF8(s, "?")
	s = strings.ReplaceAll(s, "\x00", "")
	if len(s) > max {
		s = "[…начало лога обрезано…]\n" + strings.ToValidUTF8(s[len(s)-max:], "")
	}
	return s
}

func newReportCode() string {
	b := make([]byte, reportCodeLen)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand на Linux не падает; на всякий случай — код по времени
		n := time.Now().UnixNano()
		for i := range b {
			b[i] = byte(n >> (8 * uint(i)))
		}
	}
	for i := range b {
		b[i] = reportCodeAlphabet[int(b[i])%len(reportCodeAlphabet)]
	}
	return string(b)
}

// handleReport — POST /report. Требует: Authorization: Bearer {user_token}.
func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	token := bearerToken(r)
	if token == "" {
		jsonError(w, "authorization required", http.StatusUnauthorized)
		return
	}
	// Дешёвая отсечка до чтения тела (честные клиенты шлют Content-Length)
	if r.ContentLength > reportMaxBody {
		jsonErrorCode(w, "report too large", "too_large", http.StatusRequestEntityTooLarge)
		return
	}

	// Токен принимаем и у истёкшего/отозванного ключа: именно им чаще всего нужна помощь.
	var keyID string
	if err := s.db.QueryRow(`SELECT id FROM keys WHERE user_token = ? AND activated_at IS NOT NULL`, token).Scan(&keyID); err != nil {
		jsonError(w, "token not found", http.StatusNotFound)
		return
	}

	// Лимит проверяем ДО чтения тела, но «тратим» только после успешного приёма:
	// битый запрос не должен лишать пользователя возможности отправить нормальный отчёт.
	if s.reportLimiter.blocked(keyID) {
		w.Header().Set("Retry-After", strconv.Itoa(int(reportRateWin/time.Second)))
		jsonErrorCode(w, "one report per 5 minutes", "rate_limited", http.StatusTooManyRequests)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, reportMaxBody)
	var req reportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			jsonErrorCode(w, "report too large", "too_large", http.StatusRequestEntityTooLarge)
			return
		}
		jsonError(w, "invalid json", http.StatusBadRequest)
		return
	}

	req.AppVersion = clampText(req.AppVersion, 32)
	req.Device = clampText(req.Device, 80)
	req.Android = clampText(req.Android, 32)
	req.Transport = clampText(req.Transport, 32)
	req.LastError = clampText(req.LastError, 300)
	req.Comment = clampText(req.Comment, reportMaxComment)
	req.Log = clampTail(req.Log, reportMaxLog)
	if strings.TrimSpace(req.Log) == "" && strings.TrimSpace(req.Comment) == "" {
		jsonError(w, "empty report", http.StatusBadRequest)
		return
	}

	now := time.Now().Unix()
	var code string
	var err error
	for i := 0; i < 5; i++ {
		code = newReportCode()
		_, err = s.db.Exec(`INSERT INTO reports
			(code, key_id, created_at, app_version, device, android, transport, last_error, comment, log)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			code, keyID, now, req.AppVersion, req.Device, req.Android, req.Transport,
			req.LastError, req.Comment, req.Log)
		if err == nil || !strings.Contains(err.Error(), "UNIQUE") {
			break
		}
	}
	if err != nil {
		log.Printf("[report] insert: %v", err)
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	s.reportLimiter.record(keyID)

	// Квота на ключ: оставляем reportKeepPerKey последних
	if _, err := s.db.Exec(`DELETE FROM reports WHERE key_id = ? AND id NOT IN
		(SELECT id FROM reports WHERE key_id = ? ORDER BY id DESC LIMIT ?)`,
		keyID, keyID, reportKeepPerKey); err != nil {
		log.Printf("[report] prune: %v", err)
	}
	log.Printf("[report] %s от ключа %s (%s, %s), %d байт лога", code, keyID, req.AppVersion, req.Device, len(req.Log))
	jsonOK(w, map[string]any{"id": code, "next_in": int(reportRateWin / time.Second)})
}

// cleanReports удаляет отчёты старше age и сверх общего потолка; возвращает, сколько удалено.
func (s *Server) cleanReports(age time.Duration) (int64, error) {
	var total int64
	res, err := s.db.Exec(`DELETE FROM reports WHERE created_at < ?`, time.Now().Add(-age).Unix())
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	total += n
	res, err = s.db.Exec(`DELETE FROM reports WHERE id NOT IN (SELECT id FROM reports ORDER BY id DESC LIMIT ?)`, reportKeepTotal)
	if err != nil {
		return total, err
	}
	n, _ = res.RowsAffected()
	return total + n, nil
}

// ── админка ──────────────────────────────────────────────────────────────────

type reportItem struct {
	ID         int64  `json:"id"`
	Code       string `json:"code"`
	KeyID      string `json:"key_id"`
	KeyNotes   string `json:"key_notes"`
	CreatedAt  int64  `json:"created_at"`
	AppVersion string `json:"app_version"`
	Device     string `json:"device"`
	Android    string `json:"android"`
	Transport  string `json:"transport"`
	LastError  string `json:"last_error"`
	Comment    string `json:"comment"`
	LogSize    int64  `json:"log_size"`
	Log        string `json:"log,omitempty"` // только в GET /admin/reports/{code}
}

// handleAdminListReports — GET /admin/reports?key=&code=&limit=&before=
func (s *Server) handleAdminListReports(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	key := strings.ToLower(strings.TrimSpace(q.Get("key")))
	code := strings.ToUpper(strings.TrimSpace(q.Get("code")))
	limit := 50
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 200 {
			jsonError(w, "limit must be an integer between 1 and 200", http.StatusBadRequest)
			return
		}
		limit = n
	}
	var before int64
	if v := q.Get("before"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 {
			jsonError(w, "before must be a non-negative integer", http.StatusBadRequest)
			return
		}
		before = n
	}

	rows, err := s.db.Query(`SELECT r.id, r.code, r.key_id, COALESCE(k.notes, ''), r.created_at,
			r.app_version, r.device, r.android, r.transport, r.last_error, r.comment, length(r.log)
		FROM reports r LEFT JOIN keys k ON k.id = r.key_id
		WHERE (? = '' OR r.key_id = ?) AND (? = '' OR r.code = ?) AND (? = 0 OR r.id < ?)
		ORDER BY r.id DESC LIMIT ?`,
		key, key, code, code, before, before, limit)
	if err != nil {
		jsonError(w, "db: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	items := []reportItem{}
	for rows.Next() {
		var it reportItem
		if err := rows.Scan(&it.ID, &it.Code, &it.KeyID, &it.KeyNotes, &it.CreatedAt, &it.AppVersion,
			&it.Device, &it.Android, &it.Transport, &it.LastError, &it.Comment, &it.LogSize); err != nil {
			jsonError(w, "db: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if len(it.Comment) > 200 {
			it.Comment = strings.ToValidUTF8(it.Comment[:200], "") + "…"
		}
		items = append(items, it)
	}
	if err := rows.Err(); err != nil {
		jsonError(w, "db: "+err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]any{"items": items})
}

// handleAdminReport — GET/DELETE /admin/reports/{code}
func (s *Server) handleAdminReport(w http.ResponseWriter, r *http.Request) {
	p := strings.TrimPrefix(r.URL.Path, "/v1")
	code := strings.ToUpper(strings.Trim(strings.TrimPrefix(p, "/admin/reports/"), "/"))
	if code == "" || len(code) > 16 {
		jsonError(w, "report code required", http.StatusBadRequest)
		return
	}
	switch r.Method {
	case http.MethodGet:
		var it reportItem
		err := s.db.QueryRow(`SELECT r.id, r.code, r.key_id, COALESCE(k.notes, ''), r.created_at,
				r.app_version, r.device, r.android, r.transport, r.last_error, r.comment, length(r.log), r.log
			FROM reports r LEFT JOIN keys k ON k.id = r.key_id WHERE r.code = ?`, code).
			Scan(&it.ID, &it.Code, &it.KeyID, &it.KeyNotes, &it.CreatedAt, &it.AppVersion,
				&it.Device, &it.Android, &it.Transport, &it.LastError, &it.Comment, &it.LogSize, &it.Log)
		if errors.Is(err, sql.ErrNoRows) {
			jsonError(w, "report not found", http.StatusNotFound)
			return
		}
		if err != nil {
			jsonError(w, "db: "+err.Error(), http.StatusInternalServerError)
			return
		}
		jsonOK(w, it)
	case http.MethodDelete:
		res, err := s.db.Exec(`DELETE FROM reports WHERE code = ?`, code)
		if err != nil {
			jsonError(w, "db: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if n, _ := res.RowsAffected(); n == 0 {
			jsonError(w, "report not found", http.StatusNotFound)
			return
		}
		jsonOK(w, map[string]bool{"deleted": true})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
