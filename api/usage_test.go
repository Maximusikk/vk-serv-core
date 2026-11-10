package main

// Тесты 2.2/2.3: usage_log + курсор /admin/usage; локальный потолок local_limit.
// Настоящий путь: addTraffic с реальной БД и реальным хендлером (без заглушек);
// systemctl/iptables в тестовой среде отсутствуют — их ошибки в deactivatePort
// игнорируются кодом, порт гасится на уровне БД.

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

// activateKeyForTest создаёт активированный ключ на порту, как делает activate,
// минуя systemctl: строки в keys и ports.
func activateKeyForTest(t *testing.T, db *DB, id string, port int, limit, localLimit int64) {
	t.Helper()
	_, err := db.Exec(`INSERT INTO keys (id, created_at, activated_at, expires_at, bytes_limit, bytes_used, local_limit, port, user_token, wrap_pass)
		VALUES (?, ?, ?, 0, ?, 0, ?, ?, 'tok', 'wrap')`, id, time.Now().Unix(), time.Now().Unix(), limit, localLimit, port)
	if err != nil {
		t.Fatalf("insert key: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO ports (port, key_id, active) VALUES (?, ?, 1)`, port, id); err != nil {
		t.Fatalf("insert port: %v", err)
	}
}

func newUsageTestServer(t *testing.T, adminToken string) *Server {
	t.Helper()
	db, err := OpenDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	s := NewServer(db.DB, &Config{InstallDir: t.TempDir(), AdminToken: adminToken})
	return s
}

func TestUsageCursorRealPath(t *testing.T) {
	s := newUsageTestServer(t, "adm")
	db := &DB{s.db}
	activateKeyForTest(t, db, "aaaa-bbbb-cccc-dddd", 56001, 0, 0)
	activateKeyForTest(t, db, "eeee-ffff-0000-1111", 56002, 0, 0)

	s.addTraffic(56001, 1000)
	s.addTraffic(56001, 500)
	s.addTraffic(56002, 250)

	// usage_log: 3 записи по порядку
	var cnt int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM usage_log`).Scan(&cnt); err != nil || cnt != 3 {
		t.Fatalf("usage_log rows: %v (%d)", err, cnt)
	}

	// Курсор с 0: агрегат по двум ключам
	var resp usageResponse
	getUsage(t, s, "since=0", &resp)
	if len(resp.Items) != 2 {
		t.Fatalf("want 2 aggregated keys, got %+v", resp.Items)
	}
	bytesByKey := map[string]int64{}
	for _, it := range resp.Items {
		bytesByKey[it.KeyID] = it.Bytes
	}
	if bytesByKey["aaaa-bbbb-cccc-dddd"] != 1500 || bytesByKey["eeee-ffff-0000-1111"] != 250 {
		t.Fatalf("aggregates wrong: %+v", bytesByKey)
	}
	if resp.Next <= 0 {
		t.Fatalf("next cursor not advanced: %d", resp.Next)
	}

	// Курсор со next: пусто
	var resp2 usageResponse
	getUsage(t, s, fmt.Sprintf("since=%d", resp.Next), &resp2)
	if len(resp2.Items) != 0 || resp2.Next != resp.Next {
		t.Fatalf("want empty page, got %+v", resp2.Items)
	}

	// Валидация параметров
	var resp3 usageResponse
	req := httptest.NewRequest(http.MethodGet, "/admin/usage?since=-1", nil)
	w := httptest.NewRecorder()
	s.handleAdminUsage(w, req)
	if w.Code != 400 {
		t.Fatalf("negative since: want 400, got %d", w.Code)
	}
	_ = resp3
}

func getUsage(t *testing.T, s *Server, query string, out *usageResponse) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/admin/usage?"+query, nil)
	req.Header.Set("X-Admin-Token", s.cfg.AdminToken)
	w := httptest.NewRecorder()
	s.handleAdminUsage(w, req)
	if w.Code != 200 {
		t.Fatalf("usage %q: HTTP %d: %s", query, w.Code, w.Body.String())
	}
	if err := json.Unmarshal(w.Body.Bytes(), out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
}

// local_limit гасит порт тем же путём, что bytes_limit: ports.active=0, keys.port=NULL.
func TestLocalLimitDeactivatesPort(t *testing.T) {
	s := newUsageTestServer(t, "adm")
	db := &DB{s.db}
	activateKeyForTest(t, db, "aaaa-bbbb-cccc-dddd", 56001, 0 /*limit*/, 500 /*local*/)

	var events []string
	s.notifyKeyEventFn = func(event, keyID, externalID string, port int) {
		events = append(events, event)
	}

	s.addTraffic(56001, 100) // ниже потолка
	var active int
	if err := s.db.QueryRow(`SELECT active FROM ports WHERE port = 56001`).Scan(&active); err != nil || active != 1 {
		t.Fatalf("port must stay active: %v (%d)", err, active)
	}

	s.addTraffic(56001, 400) // used=600 >= local_limit=500 → гасим
	if err := s.db.QueryRow(`SELECT active FROM ports WHERE port = 56001`).Scan(&active); err == nil && active == 1 {
		t.Fatal("port must be deactivated after local limit")
	}
	var port sql.NullInt64
	if err := s.db.QueryRow(`SELECT port FROM keys WHERE id = 'aaaa-bbbb-cccc-dddd'`).Scan(&port); err != nil || port.Valid {
		t.Fatalf("keys.port must be NULL: %v (%+v)", err, port)
	}
	hasLimit := false
	for _, e := range events {
		if e == "key_limit" {
			hasLimit = true
		}
	}
	if !hasLimit {
		t.Fatalf("key_limit event missing: %v", events)
	}
}

// 80% — один раз; key_limit при исчерпании bytes_limit; порт погашен.
func TestBytesLimitAnd80PercentEvent(t *testing.T) {
	s := newUsageTestServer(t, "adm")
	db := &DB{s.db}
	activateKeyForTest(t, db, "aaaa-bbbb-cccc-dddd", 56001, 1000 /*limit*/, 0)

	var events []string
	s.notifyKeyEventFn = func(event, keyID, externalID string, port int) {
		events = append(events, event)
	}

	s.addTraffic(56001, 300) // 30% — ничего
	s.addTraffic(56001, 500) // 80% — key_limit_80 один раз
	s.addTraffic(56001, 50)  // 85% — повторного key_limit_80 нет
	s.addTraffic(56001, 200) // 105% — key_limit, порт гасится

	count := func(e string) int {
		n := 0
		for _, x := range events {
			if x == e {
				n++
			}
		}
		return n
	}
	if count("key_limit_80") != 1 {
		t.Fatalf("key_limit_80 must fire exactly once, got %d (%v)", count("key_limit_80"), events)
	}
	if count("key_limit") != 1 {
		t.Fatalf("key_limit must fire once, got %d (%v)", count("key_limit"), events)
	}
	var active int
	if err := s.db.QueryRow(`SELECT active FROM ports WHERE port = 56001`).Scan(&active); err == nil && active == 1 {
		t.Fatal("port must be deactivated after bytes limit")
	}
}

// Чистка журнала старше retention.
func TestCleanUsageLog(t *testing.T) {
	s := newUsageTestServer(t, "adm")
	now := time.Now().Unix()
	s.db.Exec(`INSERT INTO usage_log (key_id, bytes, ts) VALUES ('k', 1, ?)`, now-8*24*3600)
	s.db.Exec(`INSERT INTO usage_log (key_id, bytes, ts) VALUES ('k', 2, ?)`, now-3600)

	n, err := s.cleanUsageLog(7 * 24 * time.Hour)
	if err != nil || n != 1 {
		t.Fatalf("clean: %v (%d)", err, n)
	}
	var left int
	s.db.QueryRow(`SELECT COUNT(*) FROM usage_log`).Scan(&left)
	if left != 1 {
		t.Fatalf("fresh row must survive: %d left", left)
	}
}
