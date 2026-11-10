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
	mux := http.NewServeMux()
	registerRoutes(mux, s)

	tok := masterCall(t, mux, "POST", "/v1/master/join-tokens", "", 200)["token"].(string)
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

// Создание join-токена — только с admin-token.
func TestMasterJoinTokensRequireAdmin(t *testing.T) {
	s, _ := newTestServer(t)
	s.cfg.Mode = masterMode
	s.cfg.AdminToken = "adm"
	mux := http.NewServeMux()
	registerRoutes(mux, s)
	req := httptest.NewRequest("POST", "/v1/master/join-tokens", nil)
	req.RemoteAddr = "203.0.113.11:5555"
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("join-tokens без admin-token: want 401, got %d", w.Code)
	}
}
