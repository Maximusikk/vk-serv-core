package main

// Тесты пула VK-ссылок: равномерная раздача, закрепление за ключом, управление через API.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

const (
	vkA = "https://vk.com/call/join/abc" // основная (из setupProvisionEnv)
	vkB = "https://vk.com/call/join/bbb"
	vkC = "https://vk.ru/call/join/ccc"
)

func addPoolLink(t *testing.T, s *Server, link string) {
	t.Helper()
	if _, err := s.db.Exec(`INSERT INTO vk_links (link, created_at) VALUES (?, 1)`, link); err != nil {
		t.Fatal(err)
	}
}

// pendingKey — ключ, который ещё не активировали.
func pendingKey(t *testing.T, s *Server, id string) {
	t.Helper()
	if _, err := s.db.Exec(`INSERT INTO keys (id, created_at, expires_at, bytes_limit) VALUES (?, 1, 0, 0)`, id); err != nil {
		t.Fatal(err)
	}
}

func activateKey(t *testing.T, s *Server, id string, port int) {
	t.Helper()
	if _, err := s.db.Exec(`UPDATE keys SET activated_at = 1, port = ? WHERE id = ?`, port, id); err != nil {
		t.Fatal(err)
	}
}

// Новые ключи раскладываются по ссылкам поровну; ссылка закрепляется за ключом.
func TestVKPoolDistributesEvenly(t *testing.T) {
	s, _ := newTestServer(t)
	setupProvisionEnv(t, s)
	addPoolLink(t, s, vkB)
	addPoolLink(t, s, vkC)

	got := map[string]int{}
	assigned := map[string]string{}
	for i, id := range []string{"k1", "k2", "k3", "k4", "k5", "k6"} {
		pendingKey(t, s, id)
		l := s.assignVKLink(id, "")
		activateKey(t, s, id, 56001+i)
		got[l]++
		assigned[id] = l
	}
	for _, l := range []string{vkA, vkB, vkC} {
		if got[l] != 2 {
			t.Fatalf("link %s got %d users, want 2: %v", l, got[l], got)
		}
	}
	// Повторная активация отдаёт ту же ссылку
	for id, want := range assigned {
		if again := s.assignVKLink(id, ""); again != want {
			t.Fatalf("key %s moved from %s to %s", id, want, again)
		}
	}
}

// Ключ, активированный до появления пула, остаётся на основной ссылке.
func TestVKPoolLegacyKeyStaysOnPrimary(t *testing.T) {
	s, _ := newTestServer(t)
	setupProvisionEnv(t, s)
	addPoolLink(t, s, vkB)
	insertKey(t, s, "old", 0, 0, 56001) // activated_at=1, vk_link NULL

	if l := s.assignVKLink("old", ""); l != vkA {
		t.Fatalf("legacy key must stay on primary, got %s", l)
	}
	// И он учитывается в нагрузке основной ссылки: новый ключ идёт на пустую B.
	pendingKey(t, s, "new")
	if l := s.assignVKLink("new", ""); l != vkB {
		t.Fatalf("new key must go to the empty link, got %s", l)
	}
}

// Если ссылку убрали из пула, ключ получает другую при следующей активации.
func TestVKPoolRemovedLinkReassigned(t *testing.T) {
	s, _ := newTestServer(t)
	setupProvisionEnv(t, s)
	addPoolLink(t, s, vkB)
	pendingKey(t, s, "k1")
	s.db.Exec(`UPDATE keys SET vk_link = ? WHERE id = 'k1'`, vkB)
	if l := s.assignVKLink("k1", ""); l != vkB {
		t.Fatalf("want stored link, got %s", l)
	}
	s.db.Exec(`DELETE FROM vk_links WHERE link = ?`, vkB)
	if l := s.assignVKLink("k1", ""); l != vkA {
		t.Fatalf("removed link must be replaced, got %s", l)
	}
}

// Без пула и без VK_LINK работает запасная ссылка от клиента.
func TestVKPoolFallbackToClientLink(t *testing.T) {
	s, _ := newTestServer(t) // config.txt нет
	pendingKey(t, s, "k1")
	if l := s.assignVKLink("k1", vkB); l != vkB {
		t.Fatalf("want fallback link, got %q", l)
	}
}

func vkLinksCall(t *testing.T, s *Server, method, body string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(method, "/admin/vk/links", strings.NewReader(body))
	rec := httptest.NewRecorder()
	s.handleAdminVKLinks(rec, req)
	return rec.Code, rec.Body.String()
}

func TestVKLinksAdminAPI(t *testing.T) {
	s, _ := newTestServer(t)
	setupProvisionEnv(t, s)

	// добавить
	if code, body := vkLinksCall(t, s, http.MethodPost, `{"vk_link":"`+vkB+`"}`); code != 200 || !strings.Contains(body, "added") {
		t.Fatalf("add: %d %s", code, body)
	}
	// дубль
	if code, body := vkLinksCall(t, s, http.MethodPost, `{"vk_link":"`+vkB+`"}`); code != 200 || !strings.Contains(body, "exists") {
		t.Fatalf("duplicate: %d %s", code, body)
	}
	// основная — дубль тоже
	if _, body := vkLinksCall(t, s, http.MethodPost, `{"vk_link":"`+vkA+`"}`); !strings.Contains(body, "exists") {
		t.Fatalf("primary as duplicate: %s", body)
	}
	// мусор
	for _, bad := range []string{`{"vk_link":"http://evil.example/x"}`, `{"vk_link":"https://vk.com/call/join/a b"}`, `{}`} {
		if code, _ := vkLinksCall(t, s, http.MethodPost, bad); code != 400 {
			t.Fatalf("bad link %s must give 400, got %d", bad, code)
		}
	}
	// список
	code, body := vkLinksCall(t, s, http.MethodGet, "")
	var list []vkLinkInfo
	if code != 200 || json.Unmarshal([]byte(body), &list) != nil || len(list) != 2 {
		t.Fatalf("list: %d %s", code, body)
	}
	if !list[0].Primary || list[0].Link != vkA || list[1].Link != vkB || list[1].Primary {
		t.Fatalf("list order/primary wrong: %+v", list)
	}
	// основную удалять нельзя
	if code, _ := vkLinksCall(t, s, http.MethodDelete, `{"vk_link":"`+vkA+`"}`); code != 400 {
		t.Fatalf("delete primary must give 400, got %d", code)
	}
	// удалить добавленную (через параметр запроса, как делает приложение) и повторно
	reqQ := httptest.NewRequest(http.MethodDelete, "/admin/vk/links?vk_link="+url.QueryEscape(vkB), nil)
	recQ := httptest.NewRecorder()
	s.handleAdminVKLinks(recQ, reqQ)
	if recQ.Code != 200 {
		t.Fatalf("delete: %d", recQ.Code)
	}
	if code, _ := vkLinksCall(t, s, http.MethodDelete, `{"vk_link":"`+vkB+`"}`); code != 404 {
		t.Fatalf("second delete must give 404, got %d", code)
	}
}
