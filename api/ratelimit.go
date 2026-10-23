package main

// Простой rate limit по IP (B5): скользящее окно на фиксированное число запросов.
// Достаточно для одного сервера; состояние в памяти, сброс при рестарте API допустим.

import (
	"net"
	"net/http"
	"sync"
	"time"
)

type ipLimiter struct {
	mu     sync.Mutex
	window time.Duration
	max    int
	hits   map[string][]time.Time
	lastGC time.Time
}

func newIPLimiter(max int, window time.Duration) *ipLimiter {
	return &ipLimiter{
		window: window,
		max:    max,
		hits:   make(map[string][]time.Time),
		lastGC: time.Now(),
	}
}

// allow регистрирует запрос с ip; false — лимит превышен.
func (l *ipLimiter) allow(ip string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

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
	if len(fresh) >= l.max {
		l.hits[ip] = fresh
		return false
	}
	l.hits[ip] = append(fresh, now)
	return true
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
)

// activateRate — лимит /activate с учётом флага -activate-rate (0 и меньше = без лимита).
func (c *Config) activateRate() int {
	if c == nil || c.ActivateRate <= 0 {
		return activateRateLimit
	}
	return c.ActivateRate
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
