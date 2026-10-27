package main

// Тест 2.3 (HTTP-путь): local_limit задаётся в create, читается в GET,
// меняется PATCH'ем — через настоящие хендлеры adminMiddleware (admin-token).

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func adminCall(t *testing.T, s *Server, mux *http.ServeMux, method, path, token string, body any) map[string]any {
	t.Helper()
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rd)
	req.Header.Set("X-Admin-Token", token)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("%s %s: HTTP %d: %s", method, path, w.Code, w.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal %s: %v", path, err)
	}
	return out
}

func TestLocalLimitCreatePatchGet(t *testing.T) {
	s := newUsageTestServer(t, "adm")
	mux := http.NewServeMux()
	registerRoutes(mux, s)

	// create с local_limit
	resp := adminCall(t, s, mux, http.MethodPost, "/admin/keys/create", "adm", map[string]any{
		"expires_days": 30, "local_limit": int64(42 * 1024 * 1024), "external_id": "ll-1",
	})
	key := resp["key"].(string)

	// GET /admin/keys/<id> → local_limit
	got := adminCall(t, s, mux, http.MethodGet, "/admin/keys/"+key, "adm", nil)
	if got["local_limit"].(float64) != 42*1024*1024 {
		t.Fatalf("create local_limit lost: %+v", got)
	}

	// PATCH local_limit=0 → убрать потолок
	upd := adminCall(t, s, mux, http.MethodPatch, "/admin/keys/"+key, "adm", map[string]any{"local_limit": 0})
	if upd["local_limit"].(float64) != 0 {
		t.Fatalf("patch local_limit: %+v", upd)
	}
	got = adminCall(t, s, mux, http.MethodGet, "/admin/keys/"+key, "adm", nil)
	if got["local_limit"].(float64) != 0 {
		t.Fatalf("local_limit must be 0 after patch: %+v", got)
	}

	// Отрицательный local_limit в create → 400
	req := httptest.NewRequest(http.MethodPost, "/admin/keys/create", bytes.NewReader([]byte(`{"expires_days":30,"local_limit":-5}`)))
	req.Header.Set("X-Admin-Token", "adm")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != 400 {
		t.Fatalf("negative local_limit: want 400, got %d", w.Code)
	}
}
