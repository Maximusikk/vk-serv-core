package main

// /master/join вызывает новая нода из install.sh: у неё есть только одноразовый
// join-токен, admin-token мастера она не знает и не отправляет.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMasterJoinWithoutAdminToken(t *testing.T) {
	s, _ := newTestServer(t)
	s.cfg.Mode = masterMode
	s.cfg.AdminToken = "adm"
	s.cfg.MasterToken = "mtk"
	mux := http.NewServeMux()
	registerRoutes(mux, s)

	tok := masterCallWithToken(t, mux, "POST", "/v1/master/join-tokens", "", 200, "X-Master-Token", "mtk")["token"].(string)
	body := `{"token":"` + tok + `","api":"203.0.113.10:7000","pin":"` +
		strings.Repeat("ab", 32) + `","master_token":"mt","name":"n"}`

	join := func() int {
		req := httptest.NewRequest("POST", "/v1/master/join", strings.NewReader(body))
		req.RemoteAddr = "203.0.113.10:5555"
		req.Header.Set("Content-Type", "application/json") // БЕЗ X-Admin-Token
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		return w.Code
	}
	if code := join(); code != 200 {
		t.Fatalf("join без admin-token: want 200, got %d", code)
	}
	if code := join(); code != 403 {
		t.Fatalf("повторный join тем же токеном: want 403, got %d", code)
	}
}

// Создание join-токена — только с X-Master-Token владельца: админ-токен
// (он у продавца) join-токены выпускать не должен.
func TestMasterJoinTokensRequireMaster(t *testing.T) {
	s, _ := newTestServer(t)
	s.cfg.Mode = masterMode
	s.cfg.AdminToken = "adm"
	s.cfg.MasterToken = "mtk"
	mux := http.NewServeMux()
	registerRoutes(mux, s)
	post := func(header, token string) int {
		req := httptest.NewRequest("POST", "/v1/master/join-tokens", nil)
		req.RemoteAddr = "203.0.113.11:5555"
		if header != "" {
			req.Header.Set(header, token)
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		return w.Code
	}
	if code := post("", ""); code != http.StatusUnauthorized {
		t.Fatalf("join-tokens без токена: want 401, got %d", code)
	}
	if code := post("X-Admin-Token", "adm"); code != http.StatusUnauthorized {
		t.Fatalf("join-tokens с админ-токеном: want 401, got %d", code)
	}
	if code := post("X-Master-Token", "mtk"); code != http.StatusOK {
		t.Fatalf("join-tokens с master-токеном: want 200, got %d", code)
	}
}

// 3.9: нода, добавленная ПОСЛЕ создания подписок, должна автоматически попасть
// во все активные подписки (pending) — досыл (resendTick, 30 с) сам заведёт на
// ней ключи. Раньше нода оставалась без ключей навсегда: dispatchSubscription
// помечает ноды только при создании подписки, а досыл ходит лишь по существующим
// строкам subscription_servers.
func TestMasterJoinBackfillsSubscriptions(t *testing.T) {
	s, _ := newTestServer(t)
	s.cfg.Mode = masterMode
	s.cfg.AdminToken = "adm"
	s.cfg.MasterToken = "mtk"
	mux := http.NewServeMux()
	registerRoutes(mux, s)

	// Две подписки до появления ноды: активная и отозванная.
	masterCall(t, mux, "POST", "/v1/master/subscriptions",
		`{"external_id":"pre-1","name":"Pre","bytes_limit":0,"expires_days":30}`, 200)
	masterCall(t, mux, "POST", "/v1/master/subscriptions",
		`{"external_id":"pre-2","name":"Gone","bytes_limit":0,"expires_days":30}`, 200)
	subGone := subIDByExt(t, s, "pre-2")
	if _, err := s.db.Exec(`UPDATE subscriptions SET revoked_at = 1 WHERE id = ?`, subGone); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	// Нода добавляется после создания подписок.
	out := masterCallWithToken(t, mux, "POST", "/v1/master/join-tokens", "", 200, "X-Master-Token", "mtk")
	tok := out["token"].(string)
	masterCall(t, mux, "POST", "/v1/master/join",
		`{"token":"`+tok+`","api":"203.0.113.20:7000","pin":"`+strings.Repeat("ab", 32)+`","master_token":"mt","name":"late"}`, 200)

	// Активная подписка получила pending-доставку на новую ноду.
	sub := subIDByExt(t, s, "pre-1")
	var rows, pending int
	if err := s.db.QueryRow(`SELECT COUNT(*), COALESCE(SUM(status='pending'),0) FROM subscription_servers WHERE sub_id = ?`, sub).
		Scan(&rows, &pending); err != nil {
		t.Fatalf("query subscription_servers: %v", err)
	}
	if rows != 1 || pending != 1 {
		t.Fatalf("активная подписка: rows=%d pending=%d, хочу 1/1", rows, pending)
	}

	// Отозванная — не получила (досылять нечего).
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM subscription_servers WHERE sub_id = ?`, subGone).
		Scan(&rows); err != nil {
		t.Fatalf("query revoked: %v", err)
	}
	if rows != 0 {
		t.Fatalf("отозванная подписка получила доставку (%d строк), не должна была", rows)
	}
}
