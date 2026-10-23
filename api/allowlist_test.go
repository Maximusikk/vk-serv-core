package main

// Тесты D2: опциональный allowlist для /admin/*.

import (
	"net/http/httptest"
	"testing"
)

func TestParseAllowList(t *testing.T) {
	nets, err := parseAllowList("1.2.3.4, 10.0.0.0/8;2001:db8::/32 ::1")
	if err != nil || len(nets) != 4 {
		t.Fatalf("parse: nets=%d err=%v", len(nets), err)
	}
	if n, err := parseAllowList(""); err != nil || n != nil {
		t.Fatalf("empty must disable allowlist: %v %v", n, err)
	}
	for _, bad := range []string{"abc", "1.2.3.4/99", "1.2.3"} {
		if _, err := parseAllowList(bad); err == nil {
			t.Fatalf("%q must be rejected", bad)
		}
	}
}

func TestIPAllowed(t *testing.T) {
	nets, _ := parseAllowList("203.0.113.5, 10.0.0.0/8")
	cases := map[string]bool{
		"203.0.113.5": true,
		"203.0.113.6": false,
		"10.20.30.40": true,
		"192.0.2.1":   false,
		"not-an-ip":   false,
		"2001:db8::1": false,
	}
	for ip, want := range cases {
		if got := ipAllowed(nets, ip); got != want {
			t.Errorf("ipAllowed(%s)=%v want %v", ip, got, want)
		}
	}
	if !ipAllowed(nil, "198.51.100.7") {
		t.Fatal("empty allowlist must allow everyone")
	}
}

// Без allowlist админка работает с любого IP; с allowlist чужой IP получает 403 даже с верным токеном,
// /health и /status остаются публичными.
func TestAdminAllowlistMiddleware(t *testing.T) {
	s, _ := newTestServer(t)
	mux := newAdminMux(t, s)

	do := func(path, remote string) int {
		req := httptest.NewRequest("GET", path, nil)
		req.RemoteAddr = remote
		req.Header.Set("X-Admin-Token", "testtok")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		return w.Code
	}

	if c := do("/admin/keys", "198.51.100.7:5555"); c != 200 {
		t.Fatalf("no allowlist: want 200, got %d", c)
	}

	s.cfg.AdminAllowNets, _ = parseAllowList("203.0.113.5")
	if c := do("/admin/keys", "198.51.100.7:5555"); c != 403 {
		t.Fatalf("foreign IP: want 403, got %d", c)
	}
	if c := do("/admin/keys", "203.0.113.5:5555"); c != 200 {
		t.Fatalf("allowed IP: want 200, got %d", c)
	}
	if c := do("/health", "198.51.100.7:5555"); c != 200 {
		t.Fatalf("/health must stay public, got %d", c)
	}
}
