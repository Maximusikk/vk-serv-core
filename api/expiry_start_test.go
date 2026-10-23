package main

// C5: срок ключа считается с момента ПЕРВОЙ АКТИВАЦИИ (on_activation, по умолчанию);
// "start":"on_create" сохраняет прежнее поведение (срок с момента создания).

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type c5Env struct {
	t   *testing.T
	mux *http.ServeMux
}

// call делает запрос и разбирает JSON-объект ответа.
func (e c5Env) call(method, path, body string, admin bool) (int, map[string]any) {
	e.t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if admin {
		req.Header.Set("X-Admin-Token", "testtok")
	}
	w := httptest.NewRecorder()
	e.mux.ServeHTTP(w, req)
	out := map[string]any{}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func num(m map[string]any, k string) int64 {
	f, _ := m[k].(float64)
	return int64(f)
}

func newC5Env(t *testing.T) (*Server, c5Env) {
	t.Helper()
	s, _ := newTestServer(t)
	setupProvisionEnv(t, s)
	s.cfg.AdminToken = "testtok"
	mux := http.NewServeMux()
	registerRoutes(mux, s)
	return s, c5Env{t: t, mux: mux}
}

func (e c5Env) createKey(body string) (string, map[string]any) {
	e.t.Helper()
	code, out := e.call("POST", "/admin/keys/create", body, true)
	if code != 200 {
		e.t.Fatalf("create %s: %d %v", body, code, out)
	}
	return out["key"].(string), out
}

// По умолчанию create = on_activation: expires_at=0, duration_days=N; срок пошёл только при активации.
func TestExpiryStartsOnActivation(t *testing.T) {
	s, e := newC5Env(t)

	key, out := e.createKey(`{"expires_days": 30}`)
	if num(out, "expires_at") != 0 || num(out, "duration_days") != 30 || out["start"] != "on_activation" {
		t.Fatalf("create response: %v", out)
	}

	// До активации: статус pending, days_left = весь срок, не active
	code, got := e.call("GET", "/admin/keys/"+key, "", true)
	if code != 200 || num(got, "expires_at") != 0 || num(got, "days_left") != 30 || got["active"] != false {
		t.Fatalf("pending key: %d %v", code, got)
	}

	// Время идёт, а ключ лежит неактивированным (создан 20 дней назад) — срок не движется
	s.db.Exec(`UPDATE keys SET created_at = created_at - 20*86400 WHERE id = ?`, key)
	_, got = e.call("GET", "/admin/keys/"+key, "", true)
	if num(got, "days_left") != 30 {
		t.Fatalf("days_left must stay 30 before activation, got %v", got["days_left"])
	}

	// Первая активация: срок = момент активации + 30 дней
	before := time.Now().Unix()
	code, act := e.call("POST", "/activate", `{"key":"`+strings.ToUpper(key)+`","device_id":"dev1"}`, false)
	if code != 200 {
		t.Fatalf("activate: %d %v", code, act)
	}
	exp := num(act, "expires_at")
	if exp < before+30*86400 || exp > time.Now().Unix()+30*86400 {
		t.Fatalf("expires_at %d not ~now+30d (before=%d)", exp, before)
	}
	var dbExp int64
	s.db.QueryRow(`SELECT expires_at FROM keys WHERE id = ?`, key).Scan(&dbExp)
	if dbExp != exp {
		t.Fatalf("db expires_at %d != response %d", dbExp, exp)
	}

	// Повторная активация тем же устройством срок НЕ сдвигает
	s.db.Exec(`UPDATE keys SET expires_at = ? WHERE id = ?`, exp-1000, key)
	code, act = e.call("POST", "/activate", `{"key":"`+key+`","device_id":"dev1"}`, false)
	if code != 200 || num(act, "expires_at") != exp-1000 {
		t.Fatalf("re-activate must not reset expiry: %d %v (want %d)", code, act, exp-1000)
	}

	// Продление активированного ключа — как раньше: от текущего конца срока
	code, pr := e.call("PATCH", "/admin/keys/"+key, `{"expires_days": 5}`, true)
	if code != 200 || num(pr, "expires_at") != exp-1000+5*86400 {
		t.Fatalf("patch activated: %d %v (want %d)", code, pr, exp-1000+5*86400)
	}
}

// Продление ещё не активированного ключа добавляет дни к сроку и НЕ запускает отсчёт.
func TestPatchPendingKeyKeepsClockStopped(t *testing.T) {
	s, e := newC5Env(t)
	key, _ := e.createKey(`{"expires_days": 30}`)

	code, pr := e.call("PATCH", "/admin/keys/"+key, `{"expires_days": 10}`, true)
	if code != 200 || num(pr, "duration_days") != 40 || num(pr, "expires_at") != 0 {
		t.Fatalf("patch pending: %d %v", code, pr)
	}
	var dbExp, dbDur int64
	s.db.QueryRow(`SELECT expires_at, COALESCE(duration_days,0) FROM keys WHERE id = ?`, key).Scan(&dbExp, &dbDur)
	if dbExp != 0 || dbDur != 40 {
		t.Fatalf("db after patch: expires_at=%d duration_days=%d", dbExp, dbDur)
	}

	// Потолок суммарного срока
	code, _ = e.call("PATCH", "/admin/keys/"+key, `{"expires_days": 3650}`, true)
	if code != 400 {
		t.Fatalf("total > 3650 must be 400, got %d", code)
	}

	// «Сделать бессрочным» снимает ожидание срока
	code, pr = e.call("PATCH", "/admin/keys/"+key, `{"expires_days": 0}`, true)
	if code != 200 || num(pr, "duration_days") != 0 || num(pr, "expires_at") != 0 {
		t.Fatalf("patch to perpetual: %d %v", code, pr)
	}
	_, act := e.call("POST", "/activate", `{"key":"`+key+`","device_id":"dev1"}`, false)
	if num(act, "expires_at") != 0 {
		t.Fatalf("perpetual key got expiry after activation: %v", act)
	}
}

// Явный on_create — прежнее поведение; неизвестный start — 400; unlimited не получает срока.
func TestCreateStartModes(t *testing.T) {
	s, e := newC5Env(t)

	now := time.Now().Unix()
	_, out := e.createKey(`{"expires_days": 10, "start": "on_create"}`)
	if got := num(out, "expires_at"); got < now+10*86400 || got > now+10*86400+5 || num(out, "duration_days") != 0 || out["start"] != "on_create" {
		t.Fatalf("on_create: %v", out)
	}

	if code, _ := e.call("POST", "/admin/keys/create", `{"expires_days": 10, "start": "sometime"}`, true); code != 400 {
		t.Fatalf("unknown start must be 400, got %d", code)
	}

	key, out := e.createKey(`{"unlimited": true}`)
	if num(out, "expires_at") != 0 || num(out, "duration_days") != 0 || out["start"] != nil {
		t.Fatalf("unlimited: %v", out)
	}
	_, act := e.call("POST", "/activate", `{"key":"`+key+`","device_id":"dev1"}`, false)
	if num(act, "expires_at") != 0 {
		t.Fatalf("unlimited key got expiry: %v", act)
	}

	// Идемпотентность по external_id отдаёт те же срок/режим
	k1, _ := e.createKey(`{"expires_days": 30, "external_id": "ord-c5"}`)
	_, dup := e.call("POST", "/admin/keys/create", `{"expires_days": 30, "external_id": "ord-c5"}`, true)
	if dup["key"] != k1 || dup["duplicate"] != true || num(dup, "duration_days") != 30 || dup["start"] != "on_activation" {
		t.Fatalf("duplicate response: %v", dup)
	}
	var n int
	s.db.QueryRow(`SELECT COUNT(*) FROM keys WHERE external_id = 'ord-c5'`).Scan(&n)
	if n != 1 {
		t.Fatalf("external_id rows = %d", n)
	}
}

// Отказ в активации (сервер заполнен) не сжигает дни: срок пойдёт только после успешной выдачи порта.
func TestFailedActivationDoesNotBurnDays(t *testing.T) {
	s, e := newC5Env(t)
	insertKey(t, s, "k-busy", 0, 0, 56090) // занимает единственное место
	s.cfg.MaxActive = 1

	key, _ := e.createKey(`{"expires_days": 30}`)
	code, out := e.call("POST", "/activate", `{"key":"`+key+`","device_id":"dev1"}`, false)
	if code != 503 {
		t.Fatalf("full server: want 503, got %d %v", code, out)
	}
	var exp int64
	var act *int64
	s.db.QueryRow(`SELECT expires_at, activated_at FROM keys WHERE id = ?`, key).Scan(&exp, &act)
	if exp != 0 || act != nil {
		t.Fatalf("failed activation changed key: expires_at=%d activated_at=%v", exp, act)
	}

	// Место освободилось — активация проходит, срок стартует именно сейчас
	s.cfg.MaxActive = 0
	before := time.Now().Unix()
	code, out = e.call("POST", "/activate", `{"key":"`+key+`","device_id":"dev1"}`, false)
	if code != 200 || num(out, "expires_at") < before+30*86400 {
		t.Fatalf("retry activation: %d %v", code, out)
	}
}
