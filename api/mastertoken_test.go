package main

// Тесты 2.4: master-token принимается только на /admin/keys*, /admin/usage,
// /admin/health; admin-token работает везде как раньше; неудачный токен
// (любой) считается лимитером неудачных админ-попыток.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func masterTokenSetup(t *testing.T) (*Server, *http.ServeMux) {
	t.Helper()
	s, _ := newTestServer(t)
	setupProvisionEnv(t, s)
	s.cfg.AdminToken = "testtok"
	s.cfg.MasterToken = "mastertok"
	mux := http.NewServeMux()
	registerRoutes(mux, s)
	return s, mux
}

func doAdmin(t *testing.T, mux *http.ServeMux, method, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = "198.51.100.50:1234"
	if token != "" {
		req.Header.Set("X-Admin-Token", token)
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	return w
}

// (1) master-token работает на /admin/health.
func TestMasterTokenHealth(t *testing.T) {
	_, mux := masterTokenSetup(t)
	if w := doAdmin(t, mux, "GET", "/admin/health", "mastertok", ""); w.Code != 200 {
		t.Fatalf("health with master token: want 200, got %d %s", w.Code, w.Body.String())
	}
}

// (2) master-token работает на /admin/keys/create.
func TestMasterTokenKeysCreate(t *testing.T) {
	_, mux := masterTokenSetup(t)
	w := doAdmin(t, mux, "POST", "/admin/keys/create", "mastertok",
		`{"expires_days":30,"bytes_limit":1073741824,"notes":"mt"}`)
	if w.Code != 200 {
		t.Fatalf("keys/create with master token: want 200, got %d %s", w.Code, w.Body.String())
	}
}

// (3) master-token НЕ работает на /admin/vk (роут вне allowlist).
func TestMasterTokenRejectedOnVK(t *testing.T) {
	_, mux := masterTokenSetup(t)
	w := doAdmin(t, mux, "PUT", "/admin/vk", "mastertok", `{"vk_link":"https://vk.com/call/join/NewLink123"}`)
	if w.Code != http.StatusUnauthorized && w.Code != http.StatusForbidden {
		t.Fatalf("vk with master token: want 401/403, got %d %s", w.Code, w.Body.String())
	}
}

// (4) неверный токен → 401 и запись в лимитере неудач.
func TestWrongTokenCountsLimiter(t *testing.T) {
	s, mux := masterTokenSetup(t)
	ip := "198.51.100.50"
	if w := doAdmin(t, mux, "GET", "/admin/health", "wrongtok", ""); w.Code != 401 {
		t.Fatalf("wrong token: want 401, got %d", w.Code)
	}
	s.adminAuthLimiter.mu.Lock()
	n := len(s.adminAuthLimiter.hits[ip])
	s.adminAuthLimiter.mu.Unlock()
	if n != 1 {
		t.Fatalf("limiter: want 1 recorded failure for %s, got %d", ip, n)
	}
	// Успешный запрос (master-token) лимитер не тратит.
	if w := doAdmin(t, mux, "GET", "/admin/health", "mastertok", ""); w.Code != 200 {
		t.Fatalf("master token after failure: want 200, got %d", w.Code)
	}
	s.adminAuthLimiter.mu.Lock()
	n = len(s.adminAuthLimiter.hits[ip])
	s.adminAuthLimiter.mu.Unlock()
	if n != 1 {
		t.Fatalf("limiter after success: want still 1, got %d", n)
	}
}

// (5) admin-token по-прежнему работает на /admin/vk (полные права).
func TestAdminTokenStillFullAccess(t *testing.T) {
	_, mux := masterTokenSetup(t)
	w := doAdmin(t, mux, "PUT", "/admin/vk", "testtok", `{"vk_link":"https://vk.com/call/join/NewLink123"}`)
	if w.Code != 200 {
		t.Fatalf("vk with admin token: want 200, got %d %s", w.Code, w.Body.String())
	}
}
