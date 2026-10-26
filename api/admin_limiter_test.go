package main

// Тесты S2: лимитер неудачных X-Admin-Token. Блокировка по IP проверяется ДО сверки
// токена, считаются только неудачи, ≥10 неудач/мин → 429 даже с верным токеном.

import (
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// fakeClock — подменяемое время для ipLimiter.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func adminLimiterSetup(t *testing.T) (func(token, remote string) int, *fakeClock) {
	t.Helper()
	s, _ := newTestServer(t)
	mux := newAdminMux(t, s)
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	s.adminAuthLimiter.now = clk.Now
	s.adminAuthLimiter.lastGC = clk.Now()
	do := func(token, remote string) int {
		req := httptest.NewRequest("GET", "/admin/keys", nil)
		req.RemoteAddr = remote
		if token != "" {
			req.Header.Set("X-Admin-Token", token)
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		return w.Code
	}
	return do, clk
}

const (
	limIP    = "198.51.100.7:4444"
	limOther = "203.0.113.9:4444"
)

// 10 неудач → 401; 11-я — 429; после этого и верный токен получает 429; другой IP не затронут.
func TestAdminLimiterBlocksAfterFailures(t *testing.T) {
	do, _ := adminLimiterSetup(t)
	for i := 1; i <= adminRateLimit; i++ {
		if c := do("wrong", limIP); c != 401 {
			t.Fatalf("failure #%d: want 401, got %d", i, c)
		}
	}
	if c := do("wrong", limIP); c != 429 {
		t.Fatalf("11th failure: want 429, got %d", c)
	}
	if c := do("testtok", limIP); c != 429 {
		t.Fatalf("valid token from blocked IP: want 429, got %d", c)
	}
	if c := do("", limIP); c != 429 {
		t.Fatalf("no token from blocked IP: want 429, got %d", c)
	}
	if c := do("testtok", limOther); c != 200 {
		t.Fatalf("other IP must not be blocked: got %d", c)
	}
}

// Успешные запросы лимит не тратят: много успехов + 9 неудач — ещё не блок.
func TestAdminLimiterSuccessDoesNotCount(t *testing.T) {
	do, _ := adminLimiterSetup(t)
	for i := 0; i < 50; i++ {
		if c := do("testtok", limIP); c != 200 {
			t.Fatalf("success #%d: want 200, got %d", i, c)
		}
	}
	for i := 0; i < adminRateLimit-1; i++ {
		if c := do("wrong", limIP); c != 401 {
			t.Fatalf("failure #%d: want 401, got %d", i, c)
		}
	}
	for i := 0; i < 20; i++ {
		if c := do("testtok", limIP); c != 200 {
			t.Fatalf("success after 9 failures: want 200, got %d", c)
		}
	}
	// десятая неудача ещё 401, после неё — блок
	if c := do("wrong", limIP); c != 401 {
		t.Fatalf("10th failure: want 401, got %d", c)
	}
	if c := do("testtok", limIP); c != 429 {
		t.Fatalf("after 10 failures: want 429, got %d", c)
	}
}

// По истечении окна доступ возвращается; заблокированные запросы окно не продлевают.
func TestAdminLimiterWindowExpires(t *testing.T) {
	do, clk := adminLimiterSetup(t)
	for i := 0; i < adminRateLimit; i++ {
		do("wrong", limIP)
	}
	if c := do("testtok", limIP); c != 429 {
		t.Fatalf("want 429, got %d", c)
	}
	clk.Add(adminRateWin / 2)
	for i := 0; i < 5; i++ {
		if c := do("wrong", limIP); c != 429 {
			t.Fatalf("still blocked mid-window: got %d", c)
		}
	}
	clk.Add(adminRateWin/2 + time.Second)
	if c := do("testtok", limIP); c != 200 {
		t.Fatalf("after window: want 200, got %d", c)
	}
	if c := do("wrong", limIP); c != 401 {
		t.Fatalf("after window failure: want 401, got %d", c)
	}
}

// allow() для /activate ведёт себя как раньше: max разрешений за окно, потом отказ, через окно — снова.
func TestIPLimiterAllowUnchanged(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	l := newIPLimiter(3, time.Minute)
	l.now = clk.Now
	for i := 0; i < 3; i++ {
		if !l.allow("1.1.1.1") {
			t.Fatalf("allow #%d must pass", i)
		}
	}
	if l.allow("1.1.1.1") {
		t.Fatal("4th allow must fail")
	}
	if !l.allow("2.2.2.2") {
		t.Fatal("other IP must pass")
	}
	clk.Add(time.Minute + time.Second)
	if !l.allow("1.1.1.1") {
		t.Fatal("after window allow must pass")
	}
}
