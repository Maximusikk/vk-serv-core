package main

// S3: пин в ссылке `link` ответа /admin/keys/create и поле tls_pin в /admin/health.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// buildUserKeyLink: pin добавляется, формат host/ключа прежний.
func TestBuildUserKeyLinkContainsPin(t *testing.T) {
	s, _ := newTestServer(t)
	s.cfg.PublicURL = "203.0.113.1:7000"
	s.cfg.TLSPin = "ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34"

	link := s.buildUserKeyLink("d454-098a")
	want := "vkturn://key/203.0.113.1:7000/d454-098a?pin=ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34"
	if link != want {
		t.Fatalf("link = %q, want %q", link, want)
	}
}

// PublicURL без схемы — как раньше (никаких https:// не добавляется).
func TestBuildUserKeyLinkNoSchemeAdded(t *testing.T) {
	s, _ := newTestServer(t)
	s.cfg.PublicURL = "example.com:7000"
	s.cfg.TLSPin = "0011" // короткий фиктивный пин для проверки префикса
	link := s.buildUserKeyLink("k")
	if strings.HasPrefix(link, "http") {
		t.Fatalf("scheme must not be added: %q", link)
	}
	if !strings.HasPrefix(link, "vkturn://key/example.com:7000/k?pin=") {
		t.Fatalf("unexpected link: %q", link)
	}
}

// Без пина (TLSPin пуст) ссылка прежнего вида, без параметра pin.
func TestBuildUserKeyLinkNoPin(t *testing.T) {
	s, _ := newTestServer(t)
	s.cfg.PublicURL = "example.com:7000"
	link := s.buildUserKeyLink("abc-def")
	if link != "vkturn://key/example.com:7000/abc-def" {
		t.Fatalf("unexpected link: %q", link)
	}
}

// Регистр ключа в ссылке — как раньше: ключ подставляется как есть (сервер
// хранит строчными, generate даёт строчные), без лишних преобразований.
func TestCreateResponseLinkKeepsKeyCaseAndPin(t *testing.T) {
	s, _ := newTestServer(t)
	s.cfg.TLSPin = "feedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedface"
	s.cfg.PublicURL = "203.0.113.1:7000"

	req := httptest.NewRequest(http.MethodPost, "/admin/keys/create",
		strings.NewReader(`{"expires_days":30}`))
	req.Header.Set("X-Admin-Token", s.cfg.AdminToken)
	w := httptest.NewRecorder()
	s.handleAdminCreateKey(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("create: status %d body %s", w.Code, w.Body.String())
	}
	var resp createKeyResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Key != strings.ToLower(resp.Key) {
		t.Fatalf("key should be lowercase, got %q", resp.Key)
	}
	wantLink := "vkturn://key/203.0.113.1:7000/" + resp.Key + "?pin=" + s.cfg.TLSPin
	if resp.Link != wantLink {
		t.Fatalf("link = %q, want %q", resp.Link, wantLink)
	}
}

// /admin/health отдаёт tls_pin из конфига.
func TestAdminHealthTlsPin(t *testing.T) {
	s, _ := newTestServer(t)
	s.cfg.TLSPin = "beefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeef"

	req := httptest.NewRequest(http.MethodGet, "/admin/health", nil)
	w := httptest.NewRecorder()
	s.handleAdminHealth(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("health: status %d body %s", w.Code, w.Body.String())
	}
	var h map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &h); err != nil {
		t.Fatal(err)
	}
	if got, _ := h["tls_pin"].(string); got != s.cfg.TLSPin {
		t.Fatalf("tls_pin = %q, want %q", got, s.cfg.TLSPin)
	}
}
