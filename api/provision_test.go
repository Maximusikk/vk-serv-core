package main

// Тесты блока A (срок/лимиты/переподъём), B1 (гонка портов), B3 (валидация), C1 (идемпотентность).
// provisionPort в тестах работает без systemd: startUserService падает на systemctl
// и уходит в fallback прямого запуска фейкового бинарника server (см. setupProvisionEnv).

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// setupProvisionEnv готовает InstallDir: config.txt с HY2_PASS/SERVER_IP и фейковый server.
func setupProvisionEnv(t *testing.T, s *Server) {
	t.Helper()
	cfg := "HY2_PASS=testhy2\nSERVER_IP=203.0.113.1\nVK_LINK=https://vk.com/call/join/abc\n"
	if err := os.WriteFile(filepath.Join(s.cfg.InstallDir, "config.txt"), []byte(cfg), 0600); err != nil {
		t.Fatal(err)
	}
	fake := filepath.Join(s.cfg.InstallDir, "server")
	// -h отвечает сразу (serverSupportsStats), рабочий запуск — спит в фоне
	script := "#!/bin/sh\nif [ \"$1\" = \"-h\" ]; then echo \"-stats-file\"; exit 0; fi\nsleep 60\n"
	if err := os.WriteFile(fake, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	// Фейковые systemctl (exit 1 → startUserService уходит в прямой запуск server)
	// и iptables — чтобы тесты не ждали настоящих в WSL/CI.
	for name, body := range map[string]string{
		"systemctl": "#!/bin/sh\nexit 1\n",
		"iptables":  "#!/bin/sh\nexit 0\n",
	} {
		if err := os.WriteFile(filepath.Join(s.cfg.InstallDir, name), []byte(body), 0755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", s.cfg.InstallDir+":"+os.Getenv("PATH"))
}

func insertKey(t *testing.T, s *Server, id string, expiresAt, bytesLimit int64, port any) {
	t.Helper()
	_, err := s.db.Exec(`INSERT INTO keys (id, created_at, activated_at, expires_at, bytes_limit, bytes_used, port, user_token, wrap_pass)
		VALUES (?, 1, 1, ?, ?, 0, ?, 'tok-old', 'wp-old')`, id, expiresAt, bytesLimit, port)
	if err != nil {
		t.Fatal(err)
	}
}

// A1: ключ с истёкшим сроком гасится тикером — порт снят, конфиг удалён.
func TestExpireOutdatedKeys(t *testing.T) {
	s, _ := newTestServer(t)
	setupProvisionEnv(t, s)
	insertKey(t, s, "k-exp", time.Now().Unix()-100, 0, 56001)
	insertKey(t, s, "k-live", time.Now().Unix()+10000, 0, 56002)

	// Фейковые файлы порта — deactivatePort должен их убрать
	os.WriteFile(s.userConfPath(56001), []byte("WRAP_PASS=x\nHY2_PASS=y\n"), 0640)
	os.WriteFile(s.statsPath(56001), []byte("1 0 0\n"), 0640)
	s.db.Exec(`INSERT INTO ports (port, key_id, active) VALUES (56001, 'k-exp', 1)`)

	s.expireOutdatedKeys()

	var port *int
	if err := s.db.QueryRow(`SELECT port FROM keys WHERE id = 'k-exp'`).Scan(&port); err != nil || port != nil {
		t.Fatalf("expired key: port should be NULL (err=%v)", err)
	}
	if _, err := os.Stat(s.userConfPath(56001)); !os.IsNotExist(err) {
		t.Fatal("user conf should be removed on expiry")
	}
	if _, err := os.Stat(s.statsPath(56001)); !os.IsNotExist(err) {
		t.Fatal("stats file should be removed on expiry")
	}
	// Живой ключ не тронут
	if err := s.db.QueryRow(`SELECT port FROM keys WHERE id = 'k-live'`).Scan(&port); err != nil || port == nil || *port != 56002 {
		t.Fatalf("live key port changed: %v", port)
	}
}

// A2/A3: переподъём после продления — новый порт, user_token сохранён.
func TestReprovisionAfterExtend(t *testing.T) {
	s, _ := newTestServer(t)
	setupProvisionEnv(t, s)
	insertKey(t, s, "k-re", 0, 0, nil) // активирован, порт погашен

	port := s.reprovisionIfDowned("k-re")
	if port == 0 {
		t.Fatal("expected reprovision to assign a port")
	}
	var (
		dbPort int
		token  string
	)
	if err := s.db.QueryRow(`SELECT port, user_token FROM keys WHERE id = 'k-re'`).Scan(&dbPort, &token); err != nil {
		t.Fatal(err)
	}
	if dbPort != port {
		t.Fatalf("db port %d != returned %d", dbPort, port)
	}
	if token != "tok-old" {
		t.Fatalf("user_token should be preserved, got %q", token)
	}
	var wrapPass string
	if err := s.db.QueryRow(`SELECT wrap_pass FROM keys WHERE id = 'k-re'`).Scan(&wrapPass); err != nil || wrapPass == "" || wrapPass == "wp-old" {
		t.Fatalf("wrap_pass should be reissued, got %q", wrapPass)
	}
	// Повторный вызов не нужен: порт уже есть
	if again := s.reprovisionIfDowned("k-re"); again != 0 {
		t.Fatalf("second call should be a no-op, got port %d", again)
	}
}

// A4: докупка трафика — лимит растёт атомарно, погашенный порт поднимается.
func TestAddTraffic(t *testing.T) {
	s, _ := newTestServer(t)
	setupProvisionEnv(t, s)
	s.cfg.AdminToken = "testtok"
	insertKey(t, s, "k-add", 0, 1000, nil) // погашен по лимиту
	insertKey(t, s, "k-unlim", 0, 0, nil)  // безлимит
	insertKey(t, s, "k-live", 0, 1000, 56050)

	mux := http.NewServeMux()
	registerRoutes(mux, s)
	ts := httptest.NewServer(mux)
	defer ts.Close()
	do := func(path, body string) *http.Response {
		req, err := http.NewRequest("POST", ts.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-Admin-Token", "testtok")
		resp, err := ts.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	// Погашенный ключ: лимит вырос + новый порт
	resp := do("/admin/keys/k-add/add_traffic", `{"bytes": 5000}`)
	out := map[string]any{}
	json.NewDecoder(resp.Body).Decode(&out)
	resp.Body.Close()
	if resp.StatusCode != 200 || out["new_port"] == nil {
		t.Fatalf("add_traffic: %d %v", resp.StatusCode, out)
	}
	var limit int64
	s.db.QueryRow(`SELECT bytes_limit FROM keys WHERE id = 'k-add'`).Scan(&limit)
	if limit != 6000 {
		t.Fatalf("bytes_limit = %d, want 6000", limit)
	}

	// Безлимитный: 400, лимит не появляется
	resp = do("/admin/keys/k-unlim/add_traffic", `{"bytes": 5000}`)
	if resp.StatusCode != 400 {
		t.Fatalf("unlimited key: want 400, got %d", resp.StatusCode)
	}
	s.db.QueryRow(`SELECT bytes_limit FROM keys WHERE id = 'k-unlim'`).Scan(&limit)
	if limit != 0 {
		t.Fatalf("unlimited key limit changed: %d", limit)
	}

	// Живой ключ: лимит растёт, порт не меняется
	resp = do("/admin/keys/k-live/add_traffic", `{"bytes": 1000}`)
	out = map[string]any{}
	json.NewDecoder(resp.Body).Decode(&out)
	resp.Body.Close()
	if resp.StatusCode != 200 || out["new_port"] != nil {
		t.Fatalf("live key: %d %v", resp.StatusCode, out)
	}
	var port int
	s.db.QueryRow(`SELECT port FROM keys WHERE id = 'k-live'`).Scan(&port)
	if port != 56050 {
		t.Fatalf("live key port changed: %d", port)
	}
}

// B1: параллельные provisionPort получают уникальные порты.
func TestConcurrentProvision(t *testing.T) {
	s, _ := newTestServer(t)
	setupProvisionEnv(t, s)
	for i := 0; i < 20; i++ {
		insertKey(t, s, fmt.Sprintf("k-%02d", i), 0, 0, nil)
	}
	var mu sync.Mutex
	ports := map[int]bool{}
	var wg sync.WaitGroup
	errs := make([]error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			prov, err := s.provisionPort(fmt.Sprintf("k-%02d", i), false)
			if err != nil {
				errs[i] = err
				return
			}
			mu.Lock()
			if ports[prov.Port] {
				errs[i] = fmt.Errorf("duplicate port %d", prov.Port)
			}
			ports[prov.Port] = true
			mu.Unlock()
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("worker %d: %v", i, err)
		}
	}
	if len(ports) != 20 {
		t.Fatalf("got %d unique ports, want 20", len(ports))
	}
}

// B3: валидация create; C1: идемпотентность по external_id.
func TestCreateKeyValidationAndIdempotency(t *testing.T) {
	s, _ := newTestServer(t)
	setupProvisionEnv(t, s)
	s.cfg.AdminToken = "testtok"
	s.cfg.PublicURL = "example.com:7000"

	mux := http.NewServeMux()
	registerRoutes(mux, s)
	ts := httptest.NewServer(mux)
	defer ts.Close()
	post := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/admin/keys/create", strings.NewReader(body))
		req.Header.Set("X-Admin-Token", "testtok")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		return w
	}

	// Негативные
	for _, body := range []string{
		`{"expires_days": -1}`,
		`{"expires_days": 99999999999}`,
		`{"expires_days": 0}`, // бессрочно — только unlimited:true
		`{"expires_days": 30, "bytes_limit": -5}`,
		`{"expires_days": 30, "notes": "` + string(make([]byte, 201)) + `"}`,
	} {
		w := post(body)
		if w.Code != 400 {
			t.Fatalf("create %s: want 400, got %d (%s)", body, w.Code, w.Body.String())
		}
	}
	var n int
	s.db.QueryRow(`SELECT COUNT(*) FROM keys`).Scan(&n)
	if n != 0 {
		t.Fatalf("invalid creates should not insert keys, got %d", n)
	}

	// Бессрочно явно
	w := post(`{"unlimited": true}`)
	if w.Code != 200 {
		t.Fatalf("unlimited create: %d %s", w.Code, w.Body.String())
	}

	// Идемпотентность: 10 повторов одного external_id = 1 ключ
	var firstKey string
	for i := 0; i < 10; i++ {
		w := post(`{"expires_days": 30, "external_id": "order-123"}`)
		if w.Code != 200 {
			t.Fatalf("create %d: %d %s", i, w.Code, w.Body.String())
		}
		var r createKeyResponse
		json.NewDecoder(w.Body).Decode(&r)
		if firstKey == "" {
			firstKey = r.Key
			if r.Link != "vkturn://key/example.com:7000/"+r.Key {
				t.Fatalf("link = %q", r.Link)
			}
		} else if r.Key != firstKey {
			t.Fatalf("duplicate external_id produced different key %s != %s", r.Key, firstKey)
		}
	}
	s.db.QueryRow(`SELECT COUNT(*) FROM keys WHERE external_id = 'order-123'`).Scan(&n)
	if n != 1 {
		t.Fatalf("external_id rows = %d, want 1", n)
	}
}

// C6: soft-revoke — ключ отзывается без удаления, активация и статус отказывают,
// повторный revoke идемпотентен, продление не поднимает порт, DELETE остаётся purge.
func TestSoftRevoke(t *testing.T) {
	s, _ := newTestServer(t)
	setupProvisionEnv(t, s)
	s.cfg.AdminToken = "testtok"
	insertKey(t, s, "k-r", time.Now().Unix()+10000, 0, 56001)
	s.db.Exec(`INSERT INTO ports (port, key_id, active) VALUES (56001, 'k-r', 1)`)
	os.WriteFile(s.userConfPath(56001), []byte("WRAP_PASS=x\nHY2_PASS=y\n"), 0640)

	mux := http.NewServeMux()
	registerRoutes(mux, s)
	do := func(method, path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, nil)
		req.Header.Set("X-Admin-Token", "testtok")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		return w
	}

	// Revoke: запись остаётся, порт погашен, конфиг удалён
	w := do("POST", "/admin/keys/k-r/revoke")
	if w.Code != 200 {
		t.Fatalf("revoke: %d %s", w.Code, w.Body.String())
	}
	var port *int
	var revokedAt *int64
	if err := s.db.QueryRow(`SELECT port, revoked_at FROM keys WHERE id = 'k-r'`).Scan(&port, &revokedAt); err != nil || port != nil || revokedAt == nil {
		t.Fatalf("after revoke: port=%v revoked_at=%v err=%v", port, revokedAt, err)
	}
	if _, err := os.Stat(s.userConfPath(56001)); !os.IsNotExist(err) {
		t.Fatal("user conf should be removed on revoke")
	}

	// Повторный revoke не меняет исходный revoked_at
	first := *revokedAt
	w = do("POST", "/admin/keys/k-r/revoke")
	if w.Code != 200 {
		t.Fatalf("second revoke: %d %s", w.Code, w.Body.String())
	}
	_ = s.db.QueryRow(`SELECT revoked_at FROM keys WHERE id = 'k-r'`).Scan(&revokedAt)
	if *revokedAt != first {
		t.Fatalf("revoked_at changed on second revoke: %d != %d", *revokedAt, first)
	}

	// /activate отзывает с кодом revoked
	req := httptest.NewRequest("POST", "/activate", strings.NewReader(`{"key":"K-R","device_id":"dev1"}`))
	wa := httptest.NewRecorder()
	mux.ServeHTTP(wa, req)
	if wa.Code != 403 || !strings.Contains(wa.Body.String(), `"revoked"`) {
		t.Fatalf("activate revoked key: %d %s", wa.Code, wa.Body.String())
	}

	// /status: active=false, revoked=true
	req = httptest.NewRequest("GET", "/status", nil)
	req.Header.Set("Authorization", "Bearer tok-old")
	ws := httptest.NewRecorder()
	mux.ServeHTTP(ws, req)
	if ws.Code != 200 {
		t.Fatalf("status: %d %s", ws.Code, ws.Body.String())
	}
	var st statusResponse
	json.NewDecoder(ws.Body).Decode(&st)
	if st.Active || !st.Revoked {
		t.Fatalf("status after revoke: %+v", st)
	}

	// Список с фильтром status=revoked находит ключ
	w = do("GET", "/admin/keys?status=revoked")
	var list []keyInfo
	json.NewDecoder(w.Body).Decode(&list)
	if len(list) != 1 || list[0].ID != "k-r" || list[0].Active {
		t.Fatalf("list revoked: %s", w.Body.String())
	}

	// Продление не поднимает отозванный ключ
	s.db.Exec(`UPDATE keys SET expires_at = ? WHERE id = 'k-r'`, time.Now().Unix()+20000)
	if p := s.reprovisionIfDowned("k-r"); p != 0 {
		t.Fatalf("revoked key reprovisioned on port %d", p)
	}

	// DELETE — полный purge
	w = do("DELETE", "/admin/keys/k-r")
	if w.Code != 200 {
		t.Fatalf("purge: %d %s", w.Code, w.Body.String())
	}
	var n int
	s.db.QueryRow(`SELECT COUNT(*) FROM keys WHERE id = 'k-r'`).Scan(&n)
	if n != 0 {
		t.Fatal("purge should remove the key row")
	}
}
