package main

// Журнал админских запросов (аудит): кто, когда, что и с каким результатом.
// Пишется в обычный лог API (journal и /var/log/vkturn/api.log), строки начинаются с "AUDIT".
//
// Что НЕ пишется: тела запросов и ответов, сами токены, полные ключи подписок. Токен
// представлен «отпечатком» (первые 4 байта SHA-256) — им можно отличить один токен от другого,
// но нельзя восстановить токен. Ключи XXXX-XXXX-XXXX-XXXX в пути и query маскируются до
// первых и последних 4 символов.
//
// Пример: AUDIT ip=203.0.113.5 role=admin tok=1a2b3c4d POST /v1/master/subscriptions 200 14ms

import (
	"crypto/sha256"
	"encoding/hex"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"
)

var reAuditKey = regexp.MustCompile(`\b([0-9a-fA-F]{4})(?:-[0-9a-fA-F]{4}){2}-([0-9a-fA-F]{4})\b`)

const auditMaxTarget = 160

// statusRecorder запоминает код ответа, чтобы записать его в аудит.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	if r.status == 0 {
		r.status = code
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.ResponseWriter.Write(b)
}

func (r *statusRecorder) code() int {
	if r.status == 0 {
		return http.StatusOK
	}
	return r.status
}

// tokenFingerprint — 8 hex-символов от SHA-256 токена (пустой токен → "-").
func tokenFingerprint(token string) string {
	if token == "" {
		return "-"
	}
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:4])
}

// auditTarget — путь и query запроса без секретов, не длиннее auditMaxTarget.
func auditTarget(r *http.Request) string {
	t := r.URL.Path
	if r.URL.RawQuery != "" {
		t += "?" + r.URL.RawQuery
	}
	t = reAuditKey.ReplaceAllString(t, "$1-****-****-$2")
	t = strings.Map(func(c rune) rune {
		if c < 0x20 || c == 0x7f {
			return '_' // защита журнала от подделки строк (перевод строки в пути)
		}
		return c
	}, t)
	if len(t) > auditMaxTarget {
		t = t[:auditMaxTarget] + "…"
	}
	return t
}

// auditLog пишет одну строку аудита. role: admin | master | none (токен не принят).
// Для role=none отпечаток не пишется: это перебираемое значение, а не токен владельца.
func auditLog(r *http.Request, role, token string, status int, d time.Duration) {
	fp := "-"
	if role != "none" {
		fp = tokenFingerprint(token)
	}
	log.Printf("AUDIT ip=%s role=%s tok=%s %s %s %d %dms",
		clientIP(r), role, fp, r.Method, auditTarget(r), status, d.Milliseconds())
}
