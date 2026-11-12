package main

// Тесты POST /report и /admin/reports: приём, лимит 1/5 мин на ключ, потолок размера,
// квоты и чистка, права админа.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type reportEnv struct {
	s   *Server
	mux *http.ServeMux
	clk *fakeClock
}

func newReportEnv(t *testing.T) *reportEnv {
	t.Helper()
	s, _ := newTestServer(t)
	mux := newAdminMux(t, s) // ставит AdminToken = "testtok"
	activateKeyForTest(t, &DB{s.db}, "k-rep", 56001, 0, 0) // user_token = 'tok'
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	s.reportLimiter.now = clk.Now
	s.reportLimiter.lastGC = clk.Now()
	return &reportEnv{s: s, mux: mux, clk: clk}
}

func (e *reportEnv) post(token, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", "/report", strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	e.mux.ServeHTTP(w, req)
	return w
}

func (e *reportEnv) admin(method, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	req.Header.Set("X-Admin-Token", "testtok")
	w := httptest.NewRecorder()
	e.mux.ServeHTTP(w, req)
	return w
}

const okReport = `{"app_version":"0.5.8","device":"Xiaomi 2412DPC0AG","android":"15","transport":"direct",
"last_error":"Сервер недоступен","comment":"не подключается","log":"line1\nline2\nline3"}`

func TestReportAcceptAndAdminView(t *testing.T) {
	e := newReportEnv(t)
	w := e.post("tok", okReport)
	if w.Code != 200 {
		t.Fatalf("post: %d %s", w.Code, w.Body.String())
	}
	var resp struct {
		ID     string `json:"id"`
		NextIn int    `json:"next_in"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.ID) != reportCodeLen || resp.NextIn != 300 {
		t.Fatalf("bad response: %+v", resp)
	}
	for _, c := range resp.ID {
		if !strings.ContainsRune(reportCodeAlphabet, c) {
			t.Fatalf("code %q has char outside alphabet", resp.ID)
		}
	}

	// список: без лога, но с размером; фильтры по ключу и коду
	for _, path := range []string{"/admin/reports", "/admin/reports?key=K-REP", "/admin/reports?code=" + strings.ToLower(resp.ID)} {
		lw := e.admin("GET", path)
		if lw.Code != 200 {
			t.Fatalf("list %s: %d %s", path, lw.Code, lw.Body.String())
		}
		var list struct {
			Items []reportItem `json:"items"`
		}
		_ = json.Unmarshal(lw.Body.Bytes(), &list)
		if len(list.Items) != 1 || list.Items[0].Code != resp.ID || list.Items[0].Log != "" || list.Items[0].LogSize == 0 {
			t.Fatalf("list %s: %+v", path, list.Items)
		}
	}
	// другой ключ — пусто
	var empty struct {
		Items []reportItem `json:"items"`
	}
	_ = json.Unmarshal(e.admin("GET", "/admin/reports?key=nope").Body.Bytes(), &empty)
	if len(empty.Items) != 0 {
		t.Fatalf("foreign key must be empty: %+v", empty.Items)
	}

	// один отчёт целиком (в том числе через /v1 и в нижнем регистре)
	gw := e.admin("GET", "/v1/admin/reports/"+strings.ToLower(resp.ID))
	var one reportItem
	_ = json.Unmarshal(gw.Body.Bytes(), &one)
	if gw.Code != 200 || one.Log != "line1\nline2\nline3" || one.Device != "Xiaomi 2412DPC0AG" || one.KeyID != "k-rep" {
		t.Fatalf("get one: %d %+v", gw.Code, one)
	}

	if dw := e.admin("DELETE", "/admin/reports/"+resp.ID); dw.Code != 200 {
		t.Fatalf("delete: %d", dw.Code)
	}
	if dw := e.admin("DELETE", "/admin/reports/"+resp.ID); dw.Code != 404 {
		t.Fatalf("second delete: want 404, got %d", dw.Code)
	}
}

// Один отчёт на ключ раз в 5 минут; по истечении окна — снова можно.
func TestReportRateLimitPerKey(t *testing.T) {
	e := newReportEnv(t)
	if w := e.post("tok", okReport); w.Code != 200 {
		t.Fatalf("first: %d", w.Code)
	}
	w := e.post("tok", okReport)
	if w.Code != 429 || w.Header().Get("Retry-After") != "300" {
		t.Fatalf("second: want 429 + Retry-After 300, got %d %q", w.Code, w.Header().Get("Retry-After"))
	}
	e.clk.Add(reportRateWin - time.Second)
	if w := e.post("tok", okReport); w.Code != 429 {
		t.Fatalf("just before window end: want 429, got %d", w.Code)
	}
	e.clk.Add(2 * time.Second)
	if w := e.post("tok", okReport); w.Code != 200 {
		t.Fatalf("after window: want 200, got %d", w.Code)
	}
}

// Битый/пустой запрос не тратит лимит: следом нормальный отчёт проходит.
func TestReportBadRequestDoesNotBurnLimit(t *testing.T) {
	e := newReportEnv(t)
	if w := e.post("tok", `{not json`); w.Code != 400 {
		t.Fatalf("bad json: want 400, got %d", w.Code)
	}
	if w := e.post("tok", `{"app_version":"1"}`); w.Code != 400 {
		t.Fatalf("empty report: want 400, got %d", w.Code)
	}
	if w := e.post("tok", okReport); w.Code != 200 {
		t.Fatalf("valid after bad: want 200, got %d", w.Code)
	}
}

func TestReportAuth(t *testing.T) {
	e := newReportEnv(t)
	if w := e.post("", okReport); w.Code != 401 {
		t.Fatalf("no token: want 401, got %d", w.Code)
	}
	if w := e.post("wrong", okReport); w.Code != 404 {
		t.Fatalf("wrong token: want 404, got %d", w.Code)
	}
	req := httptest.NewRequest("GET", "/report", nil)
	req.Header.Set("Authorization", "Bearer tok")
	w := httptest.NewRecorder()
	e.mux.ServeHTTP(w, req)
	if w.Code != 405 {
		t.Fatalf("GET /report: want 405, got %d", w.Code)
	}
	// админские роуты без токена закрыты
	for _, p := range []string{"/admin/reports", "/admin/reports/ABC123"} {
		req := httptest.NewRequest("GET", p, nil)
		w := httptest.NewRecorder()
		e.mux.ServeHTTP(w, req)
		if w.Code != 401 {
			t.Fatalf("%s without token: want 401, got %d", p, w.Code)
		}
	}
	// истёкший/отозванный ключ всё равно может написать
	if _, err := e.s.db.Exec(`UPDATE keys SET revoked_at = 1, expires_at = 1 WHERE id = 'k-rep'`); err != nil {
		t.Fatal(err)
	}
	if w := e.post("tok", okReport); w.Code != 200 {
		t.Fatalf("revoked key: want 200, got %d", w.Code)
	}
}

// Потолок размера: по заголовку Content-Length и по фактическому потоку без заголовка.
func TestReportSizeCap(t *testing.T) {
	e := newReportEnv(t)
	big := `{"log":"` + strings.Repeat("a", reportMaxBody+10) + `"}`

	if w := e.post("tok", big); w.Code != 413 {
		t.Fatalf("declared size: want 413, got %d", w.Code)
	}

	req := httptest.NewRequest("POST", "/report", strings.NewReader(big))
	req.ContentLength = -1 // как chunked: заголовку верить нельзя
	req.Header.Set("Authorization", "Bearer tok")
	w := httptest.NewRecorder()
	e.mux.ServeHTTP(w, req)
	if w.Code != 413 {
		t.Fatalf("unknown size: want 413, got %d", w.Code)
	}
	var n int
	_ = e.s.db.QueryRow(`SELECT count(*) FROM reports`).Scan(&n)
	if n != 0 {
		t.Fatalf("oversized report must not be stored, have %d", n)
	}
	// после отказа лимит не потрачен
	if w := e.post("tok", okReport); w.Code != 200 {
		t.Fatalf("valid after 413: want 200, got %d", w.Code)
	}
}

// Лог до потолка тела, но больше reportMaxLog: хранится хвост; NUL и битый UTF-8 вычищаются.
func TestReportLogClampedKeepsTail(t *testing.T) {
	e := newReportEnv(t)
	logText := strings.Repeat("x", 600<<10) + "TAIL-MARKER\x00\xff"
	body, _ := json.Marshal(map[string]string{"log": logText, "comment": strings.Repeat("я", 2000)})
	w := e.post("tok", string(body))
	if w.Code != 200 {
		t.Fatalf("post: %d %s", w.Code, w.Body.String())
	}
	var stored, comment string
	if err := e.s.db.QueryRow(`SELECT log, comment FROM reports`).Scan(&stored, &comment); err != nil {
		t.Fatal(err)
	}
	if len(stored) > reportMaxLog+100 || !strings.Contains(stored, "TAIL-MARKER") || strings.ContainsRune(stored, 0) {
		t.Fatalf("log not clamped properly: len=%d", len(stored))
	}
	if !strings.HasPrefix(stored, "[…начало лога обрезано…]") {
		t.Fatalf("truncation marker missing")
	}
	if len(comment) > reportMaxComment {
		t.Fatalf("comment not clamped: %d", len(comment))
	}
}

// На ключ хранится не больше reportKeepPerKey последних отчётов.
func TestReportKeepPerKey(t *testing.T) {
	e := newReportEnv(t)
	var last string
	for i := 0; i < reportKeepPerKey+5; i++ {
		w := e.post("tok", okReport)
		if w.Code != 200 {
			t.Fatalf("post #%d: %d", i, w.Code)
		}
		var r struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &r)
		last = r.ID
		e.clk.Add(reportRateWin + time.Second)
	}
	var n int
	_ = e.s.db.QueryRow(`SELECT count(*) FROM reports WHERE key_id = 'k-rep'`).Scan(&n)
	if n != reportKeepPerKey {
		t.Fatalf("want %d reports kept, got %d", reportKeepPerKey, n)
	}
	var have int
	_ = e.s.db.QueryRow(`SELECT count(*) FROM reports WHERE code = ?`, last).Scan(&have)
	if have != 1 {
		t.Fatal("newest report must be kept")
	}
}

// Фоновая чистка: старше срока — удаляются, свежие остаются; общий потолок режет самые старые.
func TestCleanReports(t *testing.T) {
	e := newReportEnv(t)
	now := time.Now().Unix()
	ins := func(code string, ts int64) {
		if _, err := e.s.db.Exec(`INSERT INTO reports (code, key_id, created_at, log) VALUES (?, 'k-rep', ?, 'x')`, code, ts); err != nil {
			t.Fatal(err)
		}
	}
	ins("OLD111", now-int64((reportRetention+time.Hour)/time.Second))
	ins("NEW111", now-3600)
	n, err := e.s.cleanReports(reportRetention)
	if err != nil || n != 1 {
		t.Fatalf("clean: n=%d err=%v", n, err)
	}
	var c int
	_ = e.s.db.QueryRow(`SELECT count(*) FROM reports WHERE code = 'NEW111'`).Scan(&c)
	if c != 1 {
		t.Fatal("fresh report must stay")
	}

	// общий потолок
	for i := 0; i < reportKeepTotal+3; i++ {
		ins("C"+itoa(i), now)
	}
	if _, err := e.s.cleanReports(reportRetention); err != nil {
		t.Fatal(err)
	}
	_ = e.s.db.QueryRow(`SELECT count(*) FROM reports`).Scan(&c)
	if c != reportKeepTotal {
		t.Fatalf("total cap: want %d, got %d", reportKeepTotal, c)
	}
}

func TestReportListPaging(t *testing.T) {
	e := newReportEnv(t)
	for i := 0; i < 3; i++ {
		if w := e.post("tok", okReport); w.Code != 200 {
			t.Fatalf("post: %d", w.Code)
		}
		e.clk.Add(reportRateWin + time.Second)
	}
	var list struct {
		Items []reportItem `json:"items"`
	}
	_ = json.Unmarshal(e.admin("GET", "/admin/reports?limit=2").Body.Bytes(), &list)
	if len(list.Items) != 2 || list.Items[0].ID < list.Items[1].ID {
		t.Fatalf("limit/order: %+v", list.Items)
	}
	before := list.Items[1].ID
	var rest struct {
		Items []reportItem `json:"items"`
	}
	_ = json.Unmarshal(e.admin("GET", "/admin/reports?before="+itoa64(before)).Body.Bytes(), &rest)
	if len(rest.Items) != 1 || rest.Items[0].ID >= before {
		t.Fatalf("before: %+v", rest.Items)
	}
	if w := e.admin("GET", "/admin/reports?limit=0"); w.Code != 400 {
		t.Fatalf("limit=0: want 400, got %d", w.Code)
	}
}
