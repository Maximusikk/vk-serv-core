package main

import (
	"database/sql"
	"sync"
)

// Server — общий контекст всех хендлеров API. Конфиг описан в main.go.
type Server struct {
	db  *sql.DB
	cfg *Config

	// provisionMu сериализует выдачу портов (allocate → conf → start → INSERT ports),
	// иначе параллельные активации получают один и тот же порт.
	provisionMu sync.Mutex

	activateLimiter  *ipLimiter // /activate по IP (B5)
	adminAuthLimiter *ipLimiter // неудачных X-Admin-Token по IP (B5)

	// 1.3: подменяемые проверка/починка порта для тестов reconcile (nil = реальный systemctl)
	reconcileCheck  func(port int) (alive bool, err error)
	reconcileRepair func(port int) error

	// 1.4: вебхук перехода порта в down/восстановление; NewServer ставит реальную
	// реализацию (sendPortDownWebhook), тесты подменяют.
	notifyPortDown func(port int, recovered bool, reason string)

	// 2.5: вебхук события ключа (key_activated/key_limit_80/key_limit/key_expired/
	// key_revoked); NewServer ставит реализацию из notify.go, тесты подменяют.
	notifyKeyEventFn func(event, keyID, externalID string, port int)
}

// NewServer создаёт Server поверх открытой БД.
func NewServer(db *sql.DB, cfg *Config) *Server {
	s := &Server{
		db:               db,
		cfg:              cfg,
		activateLimiter:  newIPLimiter(cfg.activateRate(), activateRateWin),
		adminAuthLimiter: newIPLimiter(adminRateLimit, adminRateWin),
	}
	s.notifyPortDown = s.sendPortDownWebhook
	// 2.5: реальная реализация вебхуков событий ключа
	s.notifyKeyEventFn = s.sendKeyEventWebhook
	return s
}
