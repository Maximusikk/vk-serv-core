package main

// 2.2: GET /admin/usage — дельты трафика по ключам с момента курсора.
// Журнал usage_log пишется в addTraffic (accounting.go), мастер забирает
// агрегаты сам (pull): боту не нужен публичный адрес. Записи старше 7 дней
// чистятся фоново (runTrafficPoller → cleanUsageLog).

import (
	"database/sql"
	"net/http"
	"strconv"
	"time"
)

type usageItem struct {
	KeyID      string  `json:"key_id"`
	ExternalID *string `json:"external_id"` // null, если ключ без external_id
	Bytes      int64   `json:"bytes"`
}

type usageResponse struct {
	Items []usageItem `json:"items"`
	Next  int64       `json:"next"` // курсор для следующего запроса (последний id журнала)
}

const (
	usageDefaultLimit = 1000
	usageMaxLimit     = 10000
	usageRetention    = 7 * 24 * 60 * 60 // 7 дней, секунды
)

// handleAdminUsage — GET /admin/usage?since=<id>&limit=N.
// Читает до limit строк журнала после курсора, агрегирует байты по ключам.
// next — id последней прочитанной строки (равен since, если новых нет).
func (s *Server) handleAdminUsage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	since, err := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)
	if err != nil || since < 0 {
		jsonError(w, "since must be a non-negative integer", http.StatusBadRequest)
		return
	}
	limit := usageDefaultLimit
	if v := r.URL.Query().Get("limit"); v != "" {
		limit, err = strconv.Atoi(v)
		if err != nil || limit < 1 || limit > usageMaxLimit {
			jsonError(w, "limit must be an integer between 1 and 10000", http.StatusBadRequest)
			return
		}
	}

	rows, err := s.db.Query(`SELECT id, key_id, bytes FROM usage_log WHERE id > ? ORDER BY id LIMIT ?`,
		since, limit)
	if err != nil {
		jsonError(w, "db: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	agg := map[string]int64{}
	var order []string
	next := since
	for rows.Next() {
		var id int64
		var keyID string
		var bytes int64
		if err := rows.Scan(&id, &keyID, &bytes); err != nil {
			jsonError(w, "db: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if _, seen := agg[keyID]; !seen {
			order = append(order, keyID)
		}
		agg[keyID] += bytes
		next = id
	}
	if err := rows.Err(); err != nil {
		jsonError(w, "db: "+err.Error(), http.StatusInternalServerError)
		return
	}

	resp := usageResponse{Items: []usageItem{}, Next: next}
	for _, keyID := range order {
		item := usageItem{KeyID: keyID, Bytes: agg[keyID]}
		var ext sql.NullString
		if err := s.db.QueryRow(`SELECT external_id FROM keys WHERE id = ?`, keyID).Scan(&ext); err == nil && ext.Valid {
			item.ExternalID = &ext.String
		}
		resp.Items = append(resp.Items, item)
	}
	jsonOK(w, resp)
}

// cleanUsageLog удаляет записи журнала старше age и возвращает, сколько удалил.
func (s *Server) cleanUsageLog(age time.Duration) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM usage_log WHERE ts < ?`, time.Now().Add(-age).Unix())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
