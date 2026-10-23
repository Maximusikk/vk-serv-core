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
	adminAuthLimiter *ipLimiter // неудачные X-Admin-Token по IP (B5)
}

// NewServer создаёт Server поверх открытой БД.
func NewServer(db *sql.DB, cfg *Config) *Server {
	return &Server{
		db:               db,
		cfg:              cfg,
		activateLimiter:  newIPLimiter(cfg.activateRate(), activateRateWin),
		adminAuthLimiter: newIPLimiter(adminRateLimit, adminRateWin),
	}
}
