package main

import (
	"net/http"
	"strconv"
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
	// /status и /peek дёргают SQLite (MaxOpenConns(1)) — без лимита дешёвый флуд
	// вешает и активацию, и админку.
	reg("/status", rateLimitMiddleware(s.statusLimiter, s.handleStatus))
	// Peek: свежий bundle для клиента (master-mode, auth — user_token)
	reg("/peek", rateLimitMiddleware(s.statusLimiter, s.handleMasterPeek))

	// Отчёты об ошибках: Bearer user_token. До проверки токена — тот же IP-лимит, что у /status
	// (флуд невалидными токенами не должен упираться в единственное DB-соединение).
	// Лимит 1 отчёт/5 мин — по КЛЮЧУ, не по IP (из туннеля у всех IP один — IP VPS), см. report.go.
	reg("/report", rateLimitMiddleware(s.statusLimiter, s.handleReport))

	// Админские (за проверкой X-Admin-Token)
	reg("/admin/reports", s.adminMiddleware(s.handleAdminListReports))
	reg("/admin/reports/", s.adminMiddleware(s.handleAdminReport))
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
	// Опасные операции реестра нод — только с X-Master-Token владельца:
	// админ-токен (он у продавца) не должен удалять ноды и выпускать join-токены
	// (join-токен = регистрация постороннего сервера в реестре → утечка ключей).
	reg("/master/join-tokens", s.masterTokenMiddleware(s.handleMasterJoinTokens))
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
	// Жизненный цикл подписки: DELETE /{id} — удалить на всех нодах;
	// PATCH /{id} — продление; POST /{id}/add_traffic|revoke|unbind.
	reg("/master/subscriptions/", s.adminMiddleware(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/v1")
		p = strings.TrimPrefix(p, "/master/subscriptions/")
		p = strings.TrimSuffix(p, "/")
		if i := strings.IndexByte(p, '/'); i >= 0 {
			id, action := p[:i], p[i+1:]
			if _, err := strconv.ParseInt(id, 10, 64); err != nil {
				jsonError(w, "subscription id required", http.StatusBadRequest)
				return
			}
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			switch action {
			case "add_traffic":
				s.handleMasterAddTrafficSub(w, r)
			case "revoke":
				s.handleMasterRevokeSub(w, r)
			case "unbind":
				s.handleMasterUnbindSub(w, r)
			default:
				jsonError(w, "unknown action", http.StatusNotFound)
			}
			return
		}
		switch r.Method {
		case http.MethodDelete:
			s.handleMasterDeleteSub(w, r)
		case http.MethodPatch:
			s.handleMasterPatchSub(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}))
	reg("/master/servers", s.adminMiddleware(s.handleMasterListServers))
	// DELETE /master/servers/{id} — удалить ноду из реестра (только X-Master-Token)
	reg("/master/servers/", s.masterTokenMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			s.handleMasterDeleteServer(w, r)
		} else {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}))

	// Внутренние (за проверкой X-Internal)
	reg("/internal/traffic", s.handleInternalTraffic)
}
