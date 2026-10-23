package main

// Тесты G1 (PUT /admin/vk), G2 (GET /admin/health), G6 (частота unbind), C7 (/v1/).

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func newAdminMux(t *testing.T, s *Server) *http.ServeMux {
	t.Helper()
	s.cfg.AdminToken = "testtok"
	mux := http.NewServeMux()
	registerRoutes(mux, s)
	return mux
}

// G1: валидная ссылка обновляется атомарно, битая — 400, чужие ключи config.txt не трогаются.
func TestPutVKLink(t *testing.T) {
	s, _ := newTestServer(t)
	setupProvisionEnv(t, s)
	mux := newAdminMux(t, s)
	do := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("PUT", "/admin/vk", strings.NewReader(body))
		req.Header.Set("X-Admin-Token", "testtok")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		return w
	}

	good := "https://vk.com/call/join/NewLink123"
	if w := do(`{"vk_link": "` + good + `"}`); w.Code != 200 {
		t.Fatalf("put vk: %d %s", w.Code, w.Body.String())
	}
	data, _ := os.ReadFile(s.configPath())
	if !strings.Contains(string(data), "VK_LINK="+good) {
		t.Fatalf("VK_LINK not updated:\n%s", data)
	}
	if !strings.Contains(string(data), "HY2_PASS=testhy2") {
		t.Fatal("other config keys must survive VK_LINK update")
	}

	for _, bad := range []string{
		`{"vk_link": "http://vk.com/call/join/abc"}`,
		`{"vk_link": "https://evil.com/call/join/abc"}`,
		`{"vk_link": "https://vk.com/call/join/ab c"}`,
		`{"vk_link": ""}`,
	} {
		if w := do(bad); w.Code != 400 {
			t.Fatalf("bad link %s: want 400, got %d", bad, w.Code)
		}
	}
}

// G2: health отдаёт версию, аптайм, диск и статус ссылки (без сети ссылка из
// config.txt валидна по формату, probe может упасть — проверяем только поля).
func TestAdminHealth(t *testing.T) {
	s, _ := newTestServer(t)
	setupProvisionEnv(t, s)
	insertKey(t, s, "k-h", time.Now().Unix()+1000, 0, 56001)
	mux := newAdminMux(t, s)

	req := httptest.NewRequest("GET", "/admin/health", nil)
	req.Header.Set("X-Admin-Token", "testtok")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("health: %d %s", w.Code, w.Body.String())
	}
	var h adminHealth
	json.NewDecoder(w.Body).Decode(&h)
	if h.APIVersion == "" || h.UptimeSec < 0 || h.ActiveUnits != 1 || h.DiskFreeMB < 0 {
		t.Fatalf("health fields: %+v", h)
	}
	if h.VKLinkError == "" && !h.VKLinkOK {
		t.Fatalf("inconsistent vk link state: %+v", h)
	}
}

// G6: повторный unbind раньше срока — 429; после ослабления лимита — проходит.
func TestUnbindRateLimit(t *testing.T) {
	s, _ := newTestServer(t)
	setupProvisionEnv(t, s)
	s.cfg.UnbindDays = 7
	insertKey(t, s, "k-u", 0, 0, nil)
	mux := newAdminMux(t, s)
	do := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/admin/keys/k-u/unbind", nil)
		req.Header.Set("X-Admin-Token", "testtok")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		return w
	}

	if w := do(); w.Code != 200 {
		t.Fatalf("first unbind: %d %s", w.Code, w.Body.String())
	}
	w := do()
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("second unbind: want 429, got %d %s", w.Code, w.Body.String())
	}

	// Лимит снят (UnbindDays=0) — unbind снова работает
	s.cfg.UnbindDays = 0
	if w := do(); w.Code != 200 {
		t.Fatalf("unbind with limit disabled: %d %s", w.Code, w.Body.String())
	}
}

// C7: те же эндпоинты доступны под /v1/ без изменения поведения.
func TestV1Aliases(t *testing.T) {
	s, _ := newTestServer(t)
	setupProvisionEnv(t, s)
	mux := newAdminMux(t, s)

	for _, path := range []string{"/v1/health", "/v1/admin/stats", "/v1/admin/keys"} {
		req := httptest.NewRequest("GET", path, nil)
		req.Header.Set("X-Admin-Token", "testtok")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code != 200 {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
		}
	}

	req := httptest.NewRequest("POST", "/v1/activate", strings.NewReader(`{"key":"nope","device_id":"d"}`))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != 404 {
		t.Fatalf("/v1/activate: want 404, got %d", w.Code)
	}
}

// G3: -max-active — /activate отдаёт 503 при заполнении; stats показывает capacity.
func TestMaxActiveCapacity(t *testing.T) {
	s, _ := newTestServer(t)
	setupProvisionEnv(t, s)
	s.cfg.MaxActive = 1
	insertKey(t, s, "k-cap", 0, 0, nil)
	mux := newAdminMux(t, s)

	// Одно место занято другим ключом
	insertKey(t, s, "k-occ", 0, 0, 56077)

	req := httptest.NewRequest("POST", "/activate", strings.NewReader(`{"key":"k-cap","device_id":"dev1"}`))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("activate at capacity: want 503, got %d %s", w.Code, w.Body.String())
	}
	var port *int
	s.db.QueryRow(`SELECT port FROM keys WHERE id = 'k-cap'`).Scan(&port)
	if port != nil {
		t.Fatal("key must not get a port when server is full")
	}

	req = httptest.NewRequest("GET", "/admin/stats", nil)
	req.Header.Set("X-Admin-Token", "testtok")
	ws := httptest.NewRecorder()
	mux.ServeHTTP(ws, req)
	var st adminStats
	json.NewDecoder(ws.Body).Decode(&st)
	if st.Capacity != 1 || st.ActiveUnits != 1 {
		t.Fatalf("stats capacity fields: %+v", st)
	}

	// Лимит снят — активация проходит
	s.cfg.MaxActive = 0
	req = httptest.NewRequest("POST", "/activate", strings.NewReader(`{"key":"k-cap","device_id":"dev1"}`))
	w2 := httptest.NewRecorder()
	mux.ServeHTTP(w2, req)
	if w2.Code != 200 {
		t.Fatalf("activate after limit removed: %d %s", w2.Code, w2.Body.String())
	}
}
