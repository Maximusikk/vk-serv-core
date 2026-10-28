package main

// Тесты циклов мастера (3.4/3.5). nodeCall подменяется целиком через
// s.masterHTTP с фиктивным RoundTripper: он роутит по пути запроса и возвращает
// готовые JSON-ответы. Пин в тестах не проверяется — сам pinned-клиент
// покрывается интеграционными тестами, здесь проверяются циклы.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const testPinHex = "aa11bb22cc33dd44ee55ff6600112233445566778899aabbccddeeff00112233"

// fakeRT — RoundTripper, раздающий ответы по пути. fn получает запрос и
// возвращает (код, тело). Всё под мьютексом — циклы ходят из горутин.
type fakeRT struct {
	mu  sync.Mutex
	fn  func(r *http.Request) (int, string)
	revokes []string // key_id, по которым был POST .../revoke
	creates int      // сколько раз вызван keys/create
}

func (f *fakeRT) RoundTrip(r *http.Request) (*http.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case strings.HasSuffix(r.URL.Path, "/revoke"):
		f.revokes = append(f.revokes, strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/admin/keys/"), "/revoke"))
		return respOK, nil
	case strings.HasSuffix(r.URL.Path, "/keys/create"):
		f.creates++
		return respStr(http.StatusOK, `{"key":"newkey"}`), nil
	}
	code, body := f.fn(r)
	return respStr(code, body), nil
}

var respOK = &http.Response{
	StatusCode: http.StatusOK,
	Body:       io.NopCloser(strings.NewReader(`{}`)),
	Header:     http.Header{},
}

func respStr(code int, body string) *http.Response {
	return &http.Response{
		StatusCode: code,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     http.Header{},
	}
}

func (f *fakeRT) revokeCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.revokes)
}

// newMasterTestServer — сервер в режиме master с фиктивным транспортом.
func newMasterTestServer(t *testing.T, fn func(*http.Request) (int, string)) (*Server, *fakeRT) {
	t.Helper()
	s, _ := newTestServer(t)
	s.cfg.Mode = masterMode
	rt := &fakeRT{fn: fn}
	s.masterHTTP = &http.Client{Transport: rt}
	return s, rt
}

// addTestNode вставляет ноду и возвращает её id.
func addTestNode(t *testing.T, s *Server, api string) int64 {
	t.Helper()
	res, err := s.db.Exec(`INSERT INTO servers (api, pin, master_token, name, status) VALUES (?, ?, 'tok', ?, 'active')`,
		api, testPinHex, api)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := res.LastInsertId()
	return id
}

// addTestSub вставляет подписку с одной доставкой на ноду и возвращает их id.
func addTestSub(t *testing.T, s *Server, nodeID int64, extID string, limit int64) int64 {
	t.Helper()
	res, err := s.db.Exec(`INSERT INTO subscriptions (external_id, bytes_limit) VALUES (?, ?)`, extID, limit)
	if err != nil {
		t.Fatal(err)
	}
	subID, _ := res.LastInsertId()
	_, err = s.db.Exec(`INSERT INTO subscription_servers (sub_id, server_id, key_id, status) VALUES (?, ?, 'key-' || ?, 'active')`,
		subID, nodeID, extID)
	if err != nil {
		t.Fatal(err)
	}
	return subID
}

func TestMasterTrafficUsage(t *testing.T) {
	// usage_log ноды: две записи (id 1, 2). since двигается после полного забора.
	var usageSeen []int64
	s, _ := newMasterTestServer(t, func(r *http.Request) (int, string) {
		if !strings.Contains(r.URL.Path, "/admin/usage") {
			t.Errorf("неожиданный путь: %s", r.URL.Path)
			return 500, `{}`
		}
		var since int64
		fmt.Sscanf(r.URL.Query().Get("since"), "%d", &since)
		usageSeen = append(usageSeen, since)
		type item struct {
			ID    int64  `json:"id"`
			KeyID string `json:"key_id"`
			Bytes int64  `json:"bytes"`
		}
		// Журнал usage ноды: записи с фиксированными id 1 и 2.
		logItems := []item{{1, "key-ext1", 300}, {2, "key-ext1", 200}}
		items := []item{}
		next := since
		for _, it := range logItems {
			if it.ID > since {
				items = append(items, it)
				next = it.ID
			}
		}
		b, _ := json.Marshal(map[string]any{"items": items, "next": next})
		return 200, string(b)
	})
	nodeID := addTestNode(t, s, "n1.example:7000")
	addTestSub(t, s, nodeID, "ext1", 0)

	s.trafficTick()

	var used, since int64
	if err := s.db.QueryRow(`SELECT bytes_used FROM subscriptions WHERE external_id='ext1'`).Scan(&used); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(`SELECT since FROM servers WHERE id=?`, nodeID).Scan(&since); err != nil {
		t.Fatal(err)
	}
	if used != 500 {
		t.Fatalf("bytes_used = %d, хочу 500", used)
	}
	if since != 2 {
		t.Fatalf("since = %d, хочу 2", since)
	}

	// Повторный тик: новых записей нет, счётчик не растёт.
	s.trafficTick()
	s.db.QueryRow(`SELECT bytes_used FROM subscriptions WHERE external_id='ext1'`).Scan(&used)
	if used != 500 {
		t.Fatalf("после второго тика bytes_used = %d, хочу 500", used)
	}
	if len(usageSeen) < 2 || usageSeen[1] != 2 {
		t.Fatalf("второй запрос должен идти с since=2, got %v", usageSeen)
	}
}

func TestMasterTrafficNodeDownCursorStays(t *testing.T) {
	fail := true
	s, _ := newMasterTestServer(t, func(r *http.Request) (int, string) {
		if fail {
			return 503, `{"error":"node down"}`
		}
		return 200, `{"items":[],"next":7}`
	})
	nodeID := addTestNode(t, s, "n2.example:7000")
	addTestSub(t, s, nodeID, "ext1", 0)

	s.trafficTick() // сбой ноды
	var since, used int64
	s.db.QueryRow(`SELECT since FROM servers WHERE id=?`, nodeID).Scan(&since)
	if since != 0 {
		t.Fatalf("при сбое since не должен двигаться, got %d", since)
	}

	fail = false
	s.trafficTick() // нода ожила — курсор двигается
	s.db.QueryRow(`SELECT since FROM servers WHERE id=?`, nodeID).Scan(&since)
	if since != 7 {
		t.Fatalf("после восстановления since = %d, хочу 7", since)
	}
	s.db.QueryRow(`SELECT bytes_used FROM subscriptions WHERE external_id='ext1'`).Scan(&used)
	if used != 0 {
		t.Fatalf("пустой usage не должен менять счётчик, got %d", used)
	}
}

func TestMasterTrafficLimitRevoke(t *testing.T) {
	s, rt := newMasterTestServer(t, func(r *http.Request) (int, string) {
		return 200, `{"items":[],"next":0}`
	})
	nodeID := addTestNode(t, s, "n3.example:7000")
	addTestSub(t, s, nodeID, "ext1", 1000)
	// Лимит исчерпан прямо в БД.
	s.db.Exec(`UPDATE subscriptions SET bytes_used = 1000 WHERE external_id='ext1'`)

	s.trafficTick()

	if rt.revokeCount() < 1 {
		t.Fatalf("revoke не вызван (calls=%d)", rt.revokeCount())
	}
	var revokedAt any
	if err := s.db.QueryRow(`SELECT revoked_at FROM subscriptions WHERE external_id='ext1'`).Scan(&revokedAt); err != nil {
		t.Fatal(err)
	}
	if revokedAt == nil {
		t.Fatal("revoked_at не выставлен")
	}

	// Повторный тик: отозванная не отзывается второй раз.
	n := rt.revokeCount()
	s.trafficTick()
	if rt.revokeCount() != n {
		t.Fatalf("повторный revoke: было %d, стало %d", n, rt.revokeCount())
	}
}

func TestMasterResendPending(t *testing.T) {
	// Подписка: на n1 доставка active (по ней восстанавливаем срок),
	// на n2 — pending. Досыл должен создать ключ только на n2.
	s, rt := newMasterTestServer(t, func(r *http.Request) (int, string) {
		if strings.Contains(r.URL.Path, "/admin/keys/key-ext1") {
			exp := time.Now().Add(10 * 24 * time.Hour).Unix()
			b, _ := json.Marshal(map[string]any{"expires_at": exp})
			return 200, string(b)
		}
		return 500, `{}` // usage и прочее — не важно
	})
	n1 := addTestNode(t, s, "n1.example:7000")
	n2 := addTestNode(t, s, "n2.example:7000")
	s.db.Exec(`INSERT INTO subscriptions (external_id, bytes_limit) VALUES ('ext1', 100)`)
	var subID int64
	s.db.QueryRow(`SELECT id FROM subscriptions WHERE external_id='ext1'`).Scan(&subID)
	s.db.Exec(`INSERT INTO subscription_servers VALUES (?, ?, 'key-ext1', 'active', '')`, subID, n1)
	s.db.Exec(`INSERT INTO subscription_servers VALUES (?, ?, '', 'pending', '')`, subID, n2)

	s.resendTick()

	if rt.creates != 1 {
		t.Fatalf("keys/create вызван %d раз, хочу 1 (только pending-ноде)", rt.creates)
	}
	var st, keyID string
	if err := s.db.QueryRow(`SELECT status, key_id FROM subscription_servers WHERE sub_id=? AND server_id=?`, subID, n2).
		Scan(&st, &keyID); err != nil {
		t.Fatal(err)
	}
	if st != subActive || keyID != "newkey" {
		t.Fatalf("pending-нода: status=%s key=%s, хочу active/newkey", st, keyID)
	}
	// active-доставка не тронута
	if err := s.db.QueryRow(`SELECT key_id FROM subscription_servers WHERE sub_id=? AND server_id=?`, subID, n1).
		Scan(&keyID); err != nil || keyID != "key-ext1" {
		t.Fatalf("active-доставка изменена: %v %q", err, keyID)
	}

	// Без active-доставки (все ноды недоставлены) досыл откладывается.
	s.db.Exec(`UPDATE subscription_servers SET status='failed', key_id='', error='x' WHERE sub_id=? AND server_id=?`, subID, n2)
	rt.creates = 0
	s.db.Exec(`UPDATE servers SET status='down' WHERE id=?`, n1)
	s.resendTick()
	if rt.creates != 0 {
		t.Fatalf("без active-доставки досыл должен откладываться, create вызван %d раз", rt.creates)
	}
}

func TestMasterHealthCycle(t *testing.T) {
	hooks := &hookLog{}
	hook := newTestHookServer(t, hooks)

	healthy := false
	s, _ := newMasterTestServer(t, func(r *http.Request) (int, string) {
		if strings.HasSuffix(r.URL.Path, "/admin/health") {
			if healthy {
				return 200, `{"status":"ok"}`
			}
			return 503, `{"error":"down"}`
		}
		return 500, `{}`
	})
	s.cfg.NotifyURL = hook.URL
	nodeID := addTestNode(t, s, "n4.example:7000")

	s.healthTick() // active → down
	var status string
	s.db.QueryRow(`SELECT status FROM servers WHERE id=?`, nodeID).Scan(&status)
	if status != "down" {
		t.Fatalf("после сбоя status=%s, хочу down", status)
	}
	waitHooks(t, hooks, 1, "node_down")

	healthy = true
	s.healthTick() // down → active
	s.db.QueryRow(`SELECT status FROM servers WHERE id=?`, nodeID).Scan(&status)
	if status != "active" {
		t.Fatalf("после восстановления status=%s, хочу active", status)
	}
	var lastSeen int64
	s.db.QueryRow(`SELECT last_seen FROM servers WHERE id=?`, nodeID).Scan(&lastSeen)
	if lastSeen == 0 {
		t.Fatal("last_seen не обновлён")
	}
	waitHooks(t, hooks, 2, "node_up")

	// Без NotifyURL вебхуков нет и паники тоже.
	s.cfg.NotifyURL = ""
	healthy = false
	s.healthTick()
}

func TestMasterRegisterSelfNode(t *testing.T) {
	s, _ := newMasterTestServer(t, func(r *http.Request) (int, string) { return 200, `{}` })

	// Ничего не задано — ошибки с внятным текстом.
	s.cfg.BindAddr = "0.0.0.0"
	if err := s.registerSelfNode(); err == nil || !strings.Contains(err.Error(), "PUBLIC_URL") {
		t.Fatalf("хочу ошибку про PUBLIC_URL, got %v", err)
	}
	s.cfg.BindAddr = "127.0.0.1"
	s.cfg.PublicURL = ""
	if err := s.registerSelfNode(); err == nil || !strings.Contains(err.Error(), "MASTER_TOKEN") {
		t.Fatalf("хочу ошибку про MASTER_TOKEN, got %v", err)
	}

	// Всё задано — запись создана.
	s.cfg.PublicURL = "self.example:7000"
	s.cfg.MasterToken = "mtok"
	s.cfg.MaxActive = 0
	s.cfg.PortStart, s.cfg.PortEnd = 56001, 57000
	if err := s.registerSelfNode(); err != nil {
		t.Fatal(err)
	}
	n, err := s.getNodeByAPI("self.example:7000")
	if err != nil {
		t.Fatalf("запись не создана: %v", err)
	}
	if n.Name != "self" || n.Version != APIVersion || n.MasterToken != "mtok" || n.Status != "active" {
		t.Fatalf("неожиданная запись: %+v", n)
	}
	if n.Capacity != 1000 {
		t.Fatalf("capacity = %d, хочу 1000 (PortEnd-PortStart+1)", n.Capacity)
	}
}

// ── хелперы вебхуков ─────────────────────────────────────────────────────────────

// hookLog — потокобезопасный приёмник тел вебхуков (sendNodeWebhook шлёт из горутин).
type hookLog struct {
	mu     sync.Mutex
	bodies []string
}

func (h *hookLog) add(s string) {
	h.mu.Lock()
	h.bodies = append(h.bodies, s)
	h.mu.Unlock()
}

func (h *hookLog) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.bodies)
}

func (h *hookLog) get(i int) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.bodies[i]
}

func newTestHookServer(t *testing.T, log *hookLog) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 4096)
		n, _ := r.Body.Read(buf)
		log.add(string(buf[:n]))
		w.WriteHeader(200)
	}))
}

func waitHooks(t *testing.T, log *hookLog, want int, kind string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if log.count() >= want {
			if body := log.get(want - 1); !strings.Contains(body, kind) {
				t.Fatalf("хук #%d: хочу %s, got %s", want, kind, body)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("вебхук %s не пришёл (получено %d)", kind, log.count())
}
