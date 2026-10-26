package main

// Пул VK-ссылок: ключи распределяются по нескольким звонкам, чтобы на одну ссылку не приходилось
// слишком много людей.
//
//   - Основная ссылка — VK_LINK в config.txt (как раньше, меняется PUT /admin/vk).
//   - Дополнительные — таблица vk_links (GET/POST/DELETE /admin/vk/links).
//   - При первой активации ключ получает ссылку с наименьшим числом активных ключей и
//     сохраняет её в keys.vk_link. Повторная активация отдаёт ту же ссылку.
//   - Если ссылку убрали из пула, ключ получит новую при следующей активации.

import (
	"net/http"
	"strings"
	"sync"
	"time"
)

// maxVKLinks — разумный потолок размера пула (защита от мусора в БД).
const maxVKLinks = 50

// vkAssignMu сериализует выбор ссылки: два параллельных /activate не должны видеть одинаковые счётчики.
var vkAssignMu sync.Mutex

// vkPool возвращает все пригодные ссылки: основная (если есть) первой, затем добавленные.
func (s *Server) vkPool() []string {
	var pool []string
	seen := map[string]bool{}
	add := func(l string) {
		l = strings.TrimSpace(l)
		if l == "" || seen[l] || !validVKLink(l) {
			return
		}
		seen[l] = true
		pool = append(pool, l)
	}
	if _, _, primary, err := s.readMainConfig(); err == nil {
		add(primary)
	}
	rows, err := s.db.Query(`SELECT link FROM vk_links ORDER BY created_at, link`)
	if err != nil {
		return pool
	}
	defer rows.Close()
	for rows.Next() {
		var l string
		if rows.Scan(&l) == nil {
			add(l)
		}
	}
	return pool
}

// vkUserCounts считает активных пользователей на каждой ссылке.
// Ключи без закреплённой ссылки (созданы до появления пула) относятся к основной.
func (s *Server) vkUserCounts(primary string) map[string]int {
	out := map[string]int{}
	rows, err := s.db.Query(`SELECT COALESCE(vk_link, ''), COUNT(*) FROM keys
		WHERE port IS NOT NULL AND activated_at IS NOT NULL
		GROUP BY COALESCE(vk_link, '')`)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var l string
		var n int
		if rows.Scan(&l, &n) == nil {
			if l == "" {
				l = primary
			}
			out[l] += n
		}
	}
	return out
}

// assignVKLink выбирает ссылку для ключа и закрепляет её. fallback — ссылка от клиента
// для старых установок, где пула нет вовсе.
func (s *Server) assignVKLink(keyID, fallback string) string {
	vkAssignMu.Lock()
	defer vkAssignMu.Unlock()

	pool := s.vkPool()
	if len(pool) == 0 {
		return fallback
	}

	var cur string
	var activated bool
	var activatedAt *int64
	_ = s.db.QueryRow(`SELECT COALESCE(vk_link, ''), activated_at FROM keys WHERE id = ?`, keyID).
		Scan(&cur, &activatedAt)
	activated = activatedAt != nil

	if cur != "" {
		for _, l := range pool {
			if l == cur {
				return cur
			}
		}
	}
	// Ключ активирован до появления пула и живёт на основной ссылке — не трогаем его.
	if cur == "" && activated {
		_, _ = s.db.Exec(`UPDATE keys SET vk_link = ? WHERE id = ?`, pool[0], keyID)
		return pool[0]
	}

	counts := s.vkUserCounts(pool[0])
	best := pool[0]
	for _, l := range pool[1:] {
		if counts[l] < counts[best] {
			best = l
		}
	}
	_, _ = s.db.Exec(`UPDATE keys SET vk_link = ? WHERE id = ?`, best, keyID)
	return best
}

type vkLinkInfo struct {
	Link    string `json:"vk_link"`
	Users   int    `json:"users"`
	Primary bool   `json:"primary"`
}

// handleAdminVKLinks — GET/POST/DELETE /admin/vk/links.
//
//	GET    — список ссылок с числом пользователей на каждой.
//	POST   — {"vk_link": "..."} добавить ссылку в пул.
//	DELETE — убрать: ?vk_link=<ссылка> или {"vk_link": "..."} (основную убрать нельзя — меняется через PUT /admin/vk).
func (s *Server) handleAdminVKLinks(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		pool := s.vkPool()
		list := make([]vkLinkInfo, 0, len(pool))
		if len(pool) > 0 {
			counts := s.vkUserCounts(pool[0])
			for i, l := range pool {
				list = append(list, vkLinkInfo{Link: l, Users: counts[l], Primary: i == 0 && s.isPrimaryVK(l)})
			}
		}
		jsonOK(w, list)

	case http.MethodPost:
		var req putVKRequest
		if !decodeJSON(w, r, &req) {
			return
		}
		req.VKLink = strings.TrimSpace(req.VKLink)
		if !validVKLink(req.VKLink) {
			jsonError(w, `vk_link must match ^https://vk\.(com|ru)/call/join/[A-Za-z0-9_-]+$`, http.StatusBadRequest)
			return
		}
		pool := s.vkPool()
		for _, l := range pool {
			if l == req.VKLink {
				jsonOK(w, map[string]string{"status": "exists", "vk_link": req.VKLink})
				return
			}
		}
		if len(pool) >= maxVKLinks {
			jsonError(w, "too many links", http.StatusBadRequest)
			return
		}
		if _, err := s.db.Exec(`INSERT INTO vk_links (link, created_at) VALUES (?, ?)`,
			req.VKLink, time.Now().Unix()); err != nil {
			jsonError(w, "db error: "+err.Error(), http.StatusInternalServerError)
			return
		}
		jsonOK(w, map[string]string{"status": "added", "vk_link": req.VKLink})

	case http.MethodDelete:
		// Ссылка — в параметре ?vk_link=... (Android HttpURLConnection не умеет DELETE с телом) или в JSON-теле.
		var req putVKRequest
		req.VKLink = r.URL.Query().Get("vk_link")
		if req.VKLink == "" && !decodeJSON(w, r, &req) {
			return
		}
		req.VKLink = strings.TrimSpace(req.VKLink)
		if s.isPrimaryVK(req.VKLink) {
			jsonError(w, "основная ссылка меняется через PUT /admin/vk, удалить её нельзя", http.StatusBadRequest)
			return
		}
		res, err := s.db.Exec(`DELETE FROM vk_links WHERE link = ?`, req.VKLink)
		if err != nil {
			jsonError(w, "db error: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if n, _ := res.RowsAffected(); n == 0 {
			jsonError(w, "link not found", http.StatusNotFound)
			return
		}
		jsonOK(w, map[string]string{"status": "removed", "vk_link": req.VKLink})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// isPrimaryVK — это VK_LINK из config.txt?
func (s *Server) isPrimaryVK(link string) bool {
	_, _, primary, err := s.readMainConfig()
	return err == nil && primary != "" && strings.TrimSpace(primary) == link
}
