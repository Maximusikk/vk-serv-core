package main

import (
	"net/http"
	"strings"
)

// registerRoutes собирает все роуты API.
// Каждый путь регистрируется и с префиксом /v1/, и без него (C7: версионирование,
// старые пути — алиасы).
func registerRoutes(mux *http.ServeMux, s *Server) {
	reg := func(pattern string, h http.HandlerFunc) {
		mux.HandleFunc(pattern, h)
		mux.HandleFunc("/v1"+pattern, h)
	}

	reg("/health", func(w http.ResponseWriter, r *http.Request) {
		jsonOK(w, map[string]bool{"ok": true})
	})

	// Публичные (/activate ограничен по IP — B5)
	reg("/activate", rateLimitMiddleware(s.activateLimiter, s.handleActivate))
	reg("/status", s.handleStatus)

	// Админские (за проверкой X-Admin-Token)
	reg("/admin/keys/create", s.adminMiddleware(s.handleAdminCreateKey))
	reg("/admin/keys", s.adminMiddleware(s.handleAdminListKeys))
	reg("/admin/usage", s.adminMiddleware(s.handleAdminUsage)) // 2.2: дельты трафика по курсору
	reg("/admin/vk", s.adminMiddleware(s.handleAdminPutVK))
	reg("/admin/vk/links", s.adminMiddleware(s.handleAdminVKLinks))
	reg("/admin/health", s.adminMiddleware(s.handleAdminHealth))
	reg("/admin/keys/", s.adminMiddleware(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimSuffix(r.URL.Path, "/")
		switch {
		case strings.HasSuffix(p, "/unbind"):
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			s.handleAdminUnbindKey(w, r)
		case strings.HasSuffix(p, "/add_traffic"):
			s.handleAdminAddTraffic(w, r)
		case strings.HasSuffix(p, "/revoke"):
			s.handleAdminRevokeKey(w, r)
		default:
			switch r.Method {
			case http.MethodGet:
				s.handleAdminGetKey(w, r)
			case http.MethodDelete:
				s.handleAdminDeleteKey(w, r)
			case http.MethodPatch:
				s.handleAdminPatchKey(w, r)
			default:
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			}
		}
	}))
	reg("/admin/stats", s.adminMiddleware(s.handleAdminStats))

	// Этап 3: мастер (авторизация — только admin-token мастера). В режиме node отвечают 501.
	reg("/master/join-tokens", s.adminMiddleware(s.handleMasterJoinTokens))
	// join вызывает НОВАЯ нода (install.sh JOIN_*): admin-tokenа мастера у неё нет и быть не должно.
	// Авторизация — одноразовый join-токен (192 бита) + лимит по IP, как у /activate.
	reg("/master/join", rateLimitMiddleware(s.activateLimiter, s.handleMasterJoin))
	reg("/master/subscriptions", s.adminMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			s.handleMasterCreateSub(w, r)
		} else {
			s.handleMasterListSubs(w, r)
		}
	}))
	reg("/master/servers", s.adminMiddleware(s.handleMasterListServers))

	// Внутренние (за проверкой X-Internal)
	reg("/internal/traffic", s.handleInternalTraffic)
}
