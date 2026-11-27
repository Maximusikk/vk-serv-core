package main

// Тесты журнала админских запросов: что пишется, а что нет.

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	return &buf
}

func TestAuditLogsAdminRequestWithoutSecrets(t *testing.T) {
	s, _ := newTestServer(t)
	mux := newAdminMux(t, s) // AdminToken = "testtok"
	buf := captureLog(t)

	req := httptest.NewRequest("GET", "/v1/admin/keys/d454-098a-1234-abcd?x=1", nil)
	req.RemoteAddr = "203.0.113.5:4444"
	req.Header.Set("X-Admin-Token", "testtok")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	out := buf.String()
	if !strings.Contains(out, "AUDIT ip=203.0.113.5 role=admin tok="+tokenFingerprint("testtok")) {
		t.Fatalf("нет строки аудита с ролью admin: %q", out)
	}
	if !strings.Contains(out, "GET /v1/admin/keys/d454-****-****-abcd?x=1 ") {
		t.Fatalf("ключ в пути не замаскирован: %q", out)
	}
	if strings.Contains(out, "testtok") || strings.Contains(out, "098a-1234") {
		t.Fatalf("в журнал попал секрет: %q", out)
	}
	if !strings.Contains(out, " 404 ") && !strings.Contains(out, " 200 ") {
		t.Fatalf("нет кода ответа: %q", out)
	}
}

func TestAuditLogsRejectedTokenAsNone(t *testing.T) {
	s, _ := newTestServer(t)
	mux := newAdminMux(t, s)
	buf := captureLog(t)

	req := httptest.NewRequest("GET", "/v1/admin/stats", nil)
	req.Header.Set("X-Admin-Token", "guess-123")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("ожидали 401, получили %d", w.Code)
	}
	out := buf.String()
	if !strings.Contains(out, "role=none tok=- GET /v1/admin/stats 401") {
		t.Fatalf("отказ не записан как role=none: %q", out)
	}
	if strings.Contains(out, "guess-123") || strings.Contains(out, tokenFingerprint("guess-123")) {
		t.Fatalf("перебираемый токен попал в журнал: %q", out)
	}
}

func TestAuditTargetSanitizesAndTruncates(t *testing.T) {
	req := httptest.NewRequest("GET", "/v1/admin/keys?external_id=a%0AAUDIT%20ip=1.1.1.1%20role=admin", nil)
	got := auditTarget(req)
	if strings.ContainsAny(got, "\r\n") {
		t.Fatalf("перевод строки в аудите: %q", got)
	}
	long := httptest.NewRequest("GET", "/"+strings.Repeat("a", 500), nil)
	if n := len([]rune(auditTarget(long))); n > auditMaxTarget+2 {
		t.Fatalf("путь не обрезан: %d", n)
	}
}
