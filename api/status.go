package main

import (
	"net/http"
	"strings"
	"time"
)

// ── GET /status ───────────────────────────────────────────────────────────────

type statusResponse struct {
	Active     bool  `json:"active"`
	ExpiresAt  int64 `json:"expires_at"` // unix, 0 = бессрочно
	DaysLeft   int64 `json:"days_left"`  // -1 = бессрочно
	BytesUsed  int64 `json:"bytes_used"`
	BytesLimit int64 `json:"bytes_limit"` // 0 = безлимит
	Revoked    bool  `json:"revoked"`     // soft-revoke (C6)
}

// handleStatus — GET /status
// Требует: Authorization: Bearer {user_token}
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	token := bearerToken(r)
	if token == "" {
		jsonError(w, "authorization required", http.StatusUnauthorized)
		return
	}

	row := s.db.QueryRow(`
		SELECT expires_at, bytes_used, bytes_limit, port, revoked_at
		FROM keys
		WHERE user_token = ? AND activated_at IS NOT NULL`,
		token)

	var expiresAt, bytesUsed, bytesLimit int64
	var port *int
	var revokedAt *int64
	if err := row.Scan(&expiresAt, &bytesUsed, &bytesLimit, &port, &revokedAt); err != nil {
		jsonError(w, "token not found", http.StatusNotFound)
		return
	}

	now := time.Now().Unix()

	// Активность подписки
	active := true
	if revokedAt != nil {
		active = false
	}
	if expiresAt > 0 && now > expiresAt {
		active = false
	}
	if bytesLimit > 0 && bytesUsed >= bytesLimit {
		active = false
	}
	// Если сервис был убит (порт освобождён) — тоже неактивна
	if port == nil {
		active = false
	}

	// Дней осталось
	daysLeft := int64(-1) // -1 = бессрочно
	if expiresAt > 0 {
		if now > expiresAt {
			daysLeft = 0
		} else {
			daysLeft = (expiresAt - now) / 86400
		}
	}

	jsonOK(w, statusResponse{
		Active:     active,
		ExpiresAt:  expiresAt,
		DaysLeft:   daysLeft,
		BytesUsed:  bytesUsed,
		BytesLimit: bytesLimit,
		Revoked:    revokedAt != nil,
	})
}

// bearerToken извлекает токен из заголовка Authorization: Bearer <token>
func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
}
