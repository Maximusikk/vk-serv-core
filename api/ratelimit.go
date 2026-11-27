package main

// Простой rate limit по IP (B5): скользящее окно на фиксированное число запросов.
// Достаточно для одного сервера; состояние в памяти, сброс при рестарте API допустим.

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type ipLimiter struct {
	mu     sync.Mutex
	window time.Duration
	max    int
	hits   map[string][]time.Time
	lastGC time.Time
	now    func() time.Time // источник времени (подменяется в тестах)
}

func newIPLimiter(max int, window time.Duration) *ipLimiter {
	return &ipLimiter{
		window: window,
		max:    max,
		hits:   make(map[string][]time.Time),
		lastGC: time.Now(),
		now:    time.Now,
	}
}

// freshLocked чистит окно: периодически выкидывает устаревшие IP из карты и
// возвращает отметки ip, попадающие в окно. Вызывать под l.mu.
func (l *ipLimiter) freshLocked(ip string, now time.Time) []time.Time {
	// Периодическая чистка, чтобы карта не росла бесконечно
	if now.Sub(l.lastGC) > 10*l.window {
		for k, v := range l.hits {
			if len(v) == 0 || now.Sub(v[len(v)-1]) > l.window {
				delete(l.hits, k)
			}
		}
		l.lastGC = now
	}

	arr := l.hits[ip]
	fresh := arr[:0]
	for _, t := range arr {
		if now.Sub(t) <= l.window {
			fresh = append(fresh, t)
		}
	}
	if len(fresh) == 0 {
		delete(l.hits, ip)
	} else {
		l.hits[ip] = fresh
	}
	return fresh
}

// allow регистрирует запрос с ip; false — лимит превышен (используется для /activate).
func (l *ipLimiter) allow(ip string) bool {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()

	fresh := l.freshLocked(ip, now)
	if len(fresh) >= l.max {
		return false
	}
	l.hits[ip] = append(fresh, now)
	return true
}

// blocked — true, если с ip за окно уже набрано max событий (ничего не регистрирует).
// Для админки: проверяется ДО сверки токена, поэтому при блокировке 429 получает и верный токен.
func (l *ipLimiter) blocked(ip string) bool {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.freshLocked(ip, now)) >= l.max
}

// record регистрирует одно событие (для админки — неудачную попытку токена) с ip.
func (l *ipLimiter) record(ip string) {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.hits[ip] = append(l.freshLocked(ip, now), now)
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

const (
	activateRateLimit = 10 // запросов…
	activateRateWin   = time.Minute
	adminRateLimit    = 10
	adminRateWin      = time.Minute
	statusRateLimit   = 120         // /status и /peek: дешёвый флуд сюда упирается в
	statusRateWin     = time.Minute // единственное DB-соединение (MaxOpenConns(1))
)

// activateRate — лимит /activate с учётом флага -activate-rate (0 и меньше = без лимита).
func (c *Config) activateRate() int {
	if c == nil || c.ActivateRate <= 0 {
		return activateRateLimit
	}
	return c.ActivateRate
}

const (
	activateKeyLimit     = 10 // /activate с одного ключа в минуту (загрузочный канал, loopback)
	activateUnknownLimit = 30 // /activate с неизвестными ключами через loopback — один общий бакет
)

func isLoopbackIP(ip string) bool {
	p := net.ParseIP(ip)
	return p != nil && p.IsLoopback()
}

// activateLimitMiddleware — лимит /activate.
// Обычные запросы — по IP, как раньше. Запросы из загрузочного канала (hy2-boot на этом же
// сервере) приходят с loopback, поэтому лимит по IP стал бы общим на всех клиентов канала.
// Для них лимит по КЛЮЧУ из тела: валидный ключ упирается только в свой бакет, а мусор
// (неизвестные ключи) делит один общий бакет и не может вытеснить честных владельцев ключей.
func (s *Server) activateLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
	ipMw := rateLimitMiddleware(s.activateLimiter, next)
	return func(w http.ResponseWriter, r *http.Request) {
		if s.activateKeyLimiter == nil || s.activateUnknownLimiter == nil || !isLoopbackIP(clientIP(r)) {
			ipMw(w, r)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
		if err != nil {
			jsonError(w, "invalid request body", http.StatusBadRequest)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		var req struct {
			Key string `json:"key"`
		}
		_ = json.Unmarshal(body, &req)
		key := strings.ToLower(strings.TrimSpace(req.Key))

		known := false
		if key != "" && s.db != nil {
			var one int
			known = s.db.QueryRow(`SELECT 1 FROM keys WHERE id = ?`, key).Scan(&one) == nil
		}
		var ok bool
		if known {
			ok = s.activateKeyLimiter.allow("k:" + key)
		} else {
			ok = s.activateUnknownLimiter.allow("unknown")
		}
		if !ok {
			w.Header().Set("Retry-After", "60")
			jsonErrorCode(w, "Слишком много попыток — подожди минуту", "rate_limited", http.StatusTooManyRequests)
			return
		}
		next(w, r)
	}
}

// rateLimitMiddleware ограничивает частоту запросов с одного IP.
func rateLimitMiddleware(l *ipLimiter, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !l.allow(clientIP(r)) {
			w.Header().Set("Retry-After", "60")
			jsonError(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		next(w, r)
	}
}
