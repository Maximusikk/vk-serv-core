package main

// Тесты 2.5: вебхуки событий ключа (key_activated, key_limit_80, key_limit,
// key_expired, key_revoked) — подпись X-VKTurn-Signature, payload и реальные
// пути вызова (addTraffic → key_limit_80, admin revoke → key_revoked).

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// hookEvent — полученное вебхук-событие с подписью и точным телом.
type hookEvent struct {
	Signature string
	Body      []byte
}

type hookCollector struct {
	mu     sync.Mutex
	events []hookEvent
	ch     chan hookEvent
}

func newHookCollector() *hookCollector {
	return &hookCollector{ch: make(chan hookEvent, 16)}
}

// serve возвращает httptest-сервер, собирающий POST-ы; событие уходит в канал.
func (h *hookCollector) serve() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		ev := hookEvent{Signature: r.Header.Get("X-VKTurn-Signature"), Body: body}
		h.mu.Lock()
		h.events = append(h.events, ev)
		h.mu.Unlock()
		h.ch <- ev
		w.WriteHeader(200)
	}))
}

func (h *hookCollector) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.events)
}

// wait ждёт n событий (уже полученных или поступающих) до таймаута.
func (h *hookCollector) wait(t *testing.T, n int) []hookEvent {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for h.count() < n {
		select {
		case <-h.ch:
		case <-deadline:
			t.Fatalf("wait %d events, got %d", n, h.count())
		}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.events
}

// TestKeyEventSignature: с заданным секретом заголовок X-VKTurn-Signature
// равен hex HMAC-SHA256 точного тела; external_id пуст → null; port присутствует.
func TestKeyEventSignature(t *testing.T) {
	s, _ := newTestServer(t)
	h := newHookCollector()
	ts := h.serve()
	defer ts.Close()
	s.cfg.NotifyURL = ts.URL
	s.cfg.NotifySecret = "topsecret"

	s.sendKeyEventWebhook("key_activated", "kid1", "", 56001)
	evs := h.wait(t, 1)

	mac := hmac.New(sha256.New, []byte("topsecret"))
	mac.Write(evs[0].Body)
	want := hex.EncodeToString(mac.Sum(nil))
	if evs[0].Signature != want {
		t.Fatalf("signature: got %q want %q", evs[0].Signature, want)
	}
	var p map[string]any
	if err := json.Unmarshal(evs[0].Body, &p); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	if v, ok := p["external_id"]; !ok || v != nil {
		t.Fatalf("empty external_id must serialize as null, got %v (ok=%v)", v, ok)
	}
	if p["port"].(float64) != 56001 {
		t.Fatalf("port: got %v", p["port"])
	}
	if p["key_id"] != "kid1" || p["type"] != "key_activated" {
		t.Fatalf("payload: %v", p)
	}

	// Непустой external_id уходит строкой.
	s.sendKeyEventWebhook("key_revoked", "kid2", "order-42", 0)
	evs = h.wait(t, 2)
	var p2 map[string]any
	if err := json.Unmarshal(evs[1].Body, &p2); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	if p2["external_id"] != "order-42" {
		t.Fatalf("external_id: got %v", p2["external_id"])
	}
	if _, ok := p2["port"]; ok {
		t.Fatalf("port 0 must be omitted: %s", evs[1].Body)
	}
}

// TestKeyEventNoSecret: без NotifySecret заголовок подписи не отправляется.
func TestKeyEventNoSecret(t *testing.T) {
	s, _ := newTestServer(t)
	h := newHookCollector()
	ts := h.serve()
	defer ts.Close()
	s.cfg.NotifyURL = ts.URL
	s.cfg.NotifySecret = ""

	s.sendKeyEventWebhook("key_expired", "kid3", "ext-1", 56002)
	evs := h.wait(t, 1)
	if evs[0].Signature != "" {
		t.Fatalf("no secret: signature header must be absent, got %q", evs[0].Signature)
	}
}

// TestKeyEventNoURL: NotifyURL пуст — отправки нет вообще (молча).
func TestKeyEventNoURL(t *testing.T) {
	s, _ := newTestServer(t)
	s.cfg.NotifyURL = ""
	s.sendKeyEventWebhook("key_activated", "kid4", "", 56003) // не должно паниковать
}

// TestKeyEventLimit80ViaTraffic: настоящий путь addTraffic/pollTraffic —
// key_limit_80 приходит ровно один раз (флаг limit80_notified).
func TestKeyEventLimit80ViaTraffic(t *testing.T) {
	s, dir := newTestServer(t)
	h := newHookCollector()
	ts := h.serve()
	defer ts.Close()
	s.cfg.NotifyURL = ts.URL
	s.cfg.NotifySecret = "s"

	_, err := s.db.Exec(`INSERT INTO keys (id, created_at, activated_at, expires_at, bytes_limit, external_id, port)
		VALUES ('k80', 1, 1, 0, 1000, 'order-80', 56001)`)
	if err != nil {
		t.Fatal(err)
	}
	// 900 байт из 1000 = 80% → key_limit_80, но лимит ещё не исчерпан.
	writeStats(t, dir, 56001, 1, 900, 0)
	s.pollTraffic()

	evs := h.wait(t, 1)
	var p map[string]any
	if err := json.Unmarshal(evs[0].Body, &p); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	if p["type"] != "key_limit_80" || p["key_id"] != "k80" || p["external_id"] != "order-80" {
		t.Fatalf("payload: %v", p)
	}

	// Повторный poll с теми же статами (delta = 0) — повторного события нет.
	s.pollTraffic()
	select {
	case ev := <-h.ch:
		t.Fatalf("unexpected repeat event: %s", ev.Body)
	case <-time.After(500 * time.Millisecond):
	}
	if h.count() != 1 {
		t.Fatalf("key_limit_80 must fire once, got %d", h.count())
	}
}

// TestKeyEventRevokedViaAdmin: настоящий путь через handleAdminRevokeKey —
// key_revoked приходит с external_id из БД.
func TestKeyEventRevokedViaAdmin(t *testing.T) {
	s, _ := newTestServer(t)
	h := newHookCollector()
	ts := h.serve()
	defer ts.Close()
	s.cfg.NotifyURL = ts.URL

	_, err := s.db.Exec(`INSERT INTO keys (id, created_at, expires_at, external_id) VALUES ('krev', 1, 0, 'order-rev')`)
	if err != nil {
		t.Fatal(err)
	}
	mux := newAdminMux(t, s)
	req := httptest.NewRequest("POST", "/admin/keys/krev/revoke", nil)
	req.Header.Set("X-Admin-Token", "testtok")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("revoke: %d %s", w.Code, w.Body.String())
	}

	evs := h.wait(t, 1)
	var p map[string]any
	if err := json.Unmarshal(evs[0].Body, &p); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	if p["type"] != "key_revoked" || p["key_id"] != "krev" || p["external_id"] != "order-rev" {
		t.Fatalf("payload: %v", p)
	}
}

// TestKeyEventPurgeViaAdmin: DELETE /admin/keys/{id} (purge) тоже шлёт key_revoked.
func TestKeyEventPurgeViaAdmin(t *testing.T) {
	s, _ := newTestServer(t)
	h := newHookCollector()
	ts := h.serve()
	defer ts.Close()
	s.cfg.NotifyURL = ts.URL

	if _, err := s.db.Exec(`INSERT INTO keys (id, created_at, expires_at) VALUES ('kpurge', 1, 0)`); err != nil {
		t.Fatal(err)
	}
	mux := newAdminMux(t, s)
	req := httptest.NewRequest("DELETE", "/admin/keys/kpurge", nil)
	req.Header.Set("X-Admin-Token", "testtok")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("purge: %d %s", w.Code, w.Body.String())
	}

	evs := h.wait(t, 1)
	if !strings.Contains(string(evs[0].Body), `"key_revoked"`) {
		t.Fatalf("want key_revoked, got %s", evs[0].Body)
	}
}
