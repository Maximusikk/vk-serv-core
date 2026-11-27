package main

// Лимит /activate для загрузочного канала: запросы с loopback считаются по КЛЮЧУ,
// а не по общему IP 127.0.0.1; мусорные ключи не вытесняют валидные.

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func bootActivate(mux *http.ServeMux, remote, key string) int {
	body := []byte(`{"key":"` + key + `","device_id":"dev-test"}`)
	req := httptest.NewRequest(http.MethodPost, "/activate", bytes.NewReader(body))
	req.RemoteAddr = remote
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	return w.Code
}

func TestActivateLoopbackLimitPerKey(t *testing.T) {
	s := newUsageTestServer(t, "adm")
	s.activateKeyLimiter = newIPLimiter(activateKeyLimit, activateRateWin)
	s.activateUnknownLimiter = newIPLimiter(activateUnknownLimit, activateRateWin)
	mux := http.NewServeMux()
	registerRoutes(mux, s)

	keyA := adminCall(t, s, mux, http.MethodPost, "/admin/keys/create", "adm",
		map[string]any{"expires_days": 30, "external_id": "boot-a"})["key"].(string)
	keyB := adminCall(t, s, mux, http.MethodPost, "/admin/keys/create", "adm",
		map[string]any{"expires_days": 30, "external_id": "boot-b"})["key"].(string)

	// ключ A выбирает свой лимит
	for i := 0; i < activateKeyLimit; i++ {
		if c := bootActivate(mux, "127.0.0.1:5555", keyA); c == http.StatusTooManyRequests {
			t.Fatalf("keyA request %d: unexpected 429", i)
		}
	}
	if c := bootActivate(mux, "127.0.0.1:5555", keyA); c != http.StatusTooManyRequests {
		t.Fatalf("keyA over limit: want 429, got %d", c)
	}
	// ключ B с того же loopback-IP не затронут
	if c := bootActivate(mux, "127.0.0.1:5556", keyB); c == http.StatusTooManyRequests {
		t.Fatalf("keyB must not share keyA bucket, got 429")
	}

	// мусорные ключи упираются в общий бакет, но валидный ключ B проходит
	for i := 0; i < activateUnknownLimit; i++ {
		bootActivate(mux, "127.0.0.1:6000", "deadbeefdeadbeef")
	}
	if c := bootActivate(mux, "127.0.0.1:6000", "deadbeefdeadbeef"); c != http.StatusTooManyRequests {
		t.Fatalf("unknown keys over limit: want 429, got %d", c)
	}
	if c := bootActivate(mux, "127.0.0.1:6001", keyB); c == http.StatusTooManyRequests {
		t.Fatalf("valid key must not be blocked by unknown-key flood")
	}
}

func TestActivateNonLoopbackStillPerIP(t *testing.T) {
	s := newUsageTestServer(t, "adm")
	s.activateKeyLimiter = newIPLimiter(activateKeyLimit, activateRateWin)
	s.activateUnknownLimiter = newIPLimiter(activateUnknownLimit, activateRateWin)
	s.activateLimiter = newIPLimiter(3, activateRateWin)
	mux := http.NewServeMux()
	registerRoutes(mux, s)
	for i := 0; i < 3; i++ {
		if c := bootActivate(mux, "203.0.113.7:1000", "aaaaaaaaaaaaaaaa"); c == http.StatusTooManyRequests {
			t.Fatalf("request %d: unexpected 429", i)
		}
	}
	if c := bootActivate(mux, "203.0.113.7:1000", "aaaaaaaaaaaaaaaa"); c != http.StatusTooManyRequests {
		t.Fatalf("per-IP limit lost for non-loopback: got %d", c)
	}
}
