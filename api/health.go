package main

// Автономность продавца: обновление VK-ссылки (G1) и health-отчёт (G2).

import (
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

// APIVersion — версия vkturn-api для /admin/health; переопределяется ldflags.
var APIVersion = "v1.0.3-dev"

// vkLinkRe — строгий формат VK-ссылки (тот же, что в install.sh, задача F8).
var vkLinkRe = regexp.MustCompile(`^https://vk\.(com|ru)/call/join/[A-Za-z0-9_-]+$`)

// validVKLink сообщает, пригодна ли ссылка для config.txt.
func validVKLink(s string) bool { return vkLinkRe.MatchString(s) }

// ── PUT /admin/vk (G1) ────────────────────────────────────────────────────────

type putVKRequest struct {
	VKLink string `json:"vk_link"`
}

// handleAdminPutVK атомарно обновляет VK_LINK в config.txt: запись через
// временный файл + rename, права 600 сохраняются. Валидация — как в F8.
func (s *Server) handleAdminPutVK(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut && r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req putVKRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	req.VKLink = strings.TrimSpace(req.VKLink)
	if !validVKLink(req.VKLink) {
		jsonError(w, `vk_link must match ^https://vk\.(com|ru)/call/join/[A-Za-z0-9_-]+$`, http.StatusBadRequest)
		return
	}

	if err := s.updateConfigKey("VK_LINK", req.VKLink); err != nil {
		jsonError(w, "failed to update config: "+err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]string{"status": "updated", "vk_link": req.VKLink})
}

// updateConfigKey заменяет/добавляет строку KEY=VALUE в config.txt атомарно
// (tmp-файл в том же каталоге + rename). Права файла сохраняются (600 в проде).
func (s *Server) updateConfigKey(key, value string) error {
	path := s.configPath()
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	lines := strings.Split(string(data), "\n")
	replaced := false
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), key+"=") {
			lines[i] = key + "=" + value
			replaced = true
		}
	}
	if !replaced {
		lines = append(lines, key+"="+value)
	}

	info, err := os.Stat(path)
	mode := os.FileMode(0600)
	if err == nil {
		mode = info.Mode()
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(strings.Join(lines, "\n")), mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (s *Server) configPath() string {
	return s.cfg.InstallDir + "/config.txt"
}

// ── GET /admin/health (G2) ────────────────────────────────────────────────────

type adminHealth struct {
	OK          bool   `json:"ok"`
	VKLinkOK    bool   `json:"vk_link_ok"`
	VKLinkError string `json:"vk_link_error,omitempty"`
	VKLinks     int    `json:"vk_links"`       // сколько ссылок в пуле
	VKLinksOK   int    `json:"vk_links_alive"` // сколько из них отвечают
	DiskFreeMB  int64  `json:"disk_free_mb"`
	ActiveUnits int    `json:"active_vkserv"`
	Ports       *portsHealth `json:"ports,omitempty"` // 1.4: состояния портов (nil, пока reconcile не тикнул)
	APIVersion  string `json:"api_version"`
	UptimeSec   int64  `json:"uptime_sec"`
	TLSPin      string `json:"tls_pin,omitempty"` // SPKI-пин сертификата API (S3, не секрет; пуст до создания сертификата)
}

// portsHealth — сводка состояний портов (1.2/1.4): active/down/error + время последней проверки.
type portsHealth struct {
	Active    int   `json:"active"`
	Down      int   `json:"down"`
	Error     int   `json:"error"`
	Unchecked int   `json:"unchecked"` // порт ещё не проверялся reconcile'ом
	LastCheck int64 `json:"last_check"` // unix ts самой свежей проверки; 0 = проверок не было
	DownPorts []int `json:"down_ports,omitempty"`
}

var processStart = time.Now()

func (s *Server) handleAdminHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	h := adminHealth{APIVersion: APIVersion, UptimeSec: int64(time.Since(processStart).Seconds()), TLSPin: s.cfg.TLSPin}

	// VK-ссылка: формат + пробный запрос (VK отвечает на GET звонка редиректом/страницей).
	_, _, vkLink, err := s.readMainConfig()
	if err != nil {
		h.VKLinkError = "config: " + err.Error()
	} else if vkLink == "" {
		h.VKLinkError = "VK_LINK is not set"
	} else if !validVKLink(vkLink) {
		h.VKLinkError = "VK_LINK has invalid format"
	} else {
		h.VKLinkOK = s.probeVKLink(vkLink)
		if !h.VKLinkOK {
			h.VKLinkError = "probe request failed"
		}
	}

	// Пул ссылок: пробуем все параллельно. Сервер считается здоровым, если жива хотя бы одна.
	pool := s.vkPool()
	h.VKLinks = len(pool)
	if len(pool) > 0 {
		var wg sync.WaitGroup
		var mu sync.Mutex
		for _, l := range pool {
			wg.Add(1)
			go func(link string) {
				defer wg.Done()
				if s.probeVKLink(link) {
					mu.Lock()
					h.VKLinksOK++
					mu.Unlock()
				}
			}(l)
		}
		wg.Wait()
	}

	// Свободное место на разделе установки
	var st syscall.Statfs_t
	if err := syscall.Statfs(s.cfg.InstallDir, &st); err == nil {
		h.DiskFreeMB = int64(st.Bavail) * int64(st.Bsize) / (1024 * 1024)
	}

	// Живые vkserv@: ключи с выданным портом (истёкшие/отозванные гасятся тикером)
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM keys WHERE port IS NOT NULL AND activated_at IS NOT NULL`).
		Scan(&h.ActiveUnits)

	// 1.4: состояния портов из reconcile-цикла (ports.state)
	if states, err := (&DB{s.db}).ListPortStates(); err == nil {
		p := &portsHealth{}
		for _, ps := range states {
			switch {
			case !ps.State.Valid:
				p.Unchecked++
			case ps.State.String == PortStateActive:
				p.Active++
			case ps.State.String == PortStateDown:
				p.Down++
				p.DownPorts = append(p.DownPorts, ps.Port)
			case ps.State.String == PortStateError:
				p.Error++
			}
			if ps.StateCheckedAt.Valid && ps.StateCheckedAt.Int64 > p.LastCheck {
				p.LastCheck = ps.StateCheckedAt.Int64
			}
		}
		h.Ports = p
	}

	h.OK = (h.VKLinkOK || h.VKLinksOK > 0) && h.DiskFreeMB > 100
	jsonOK(w, h)
}

// probeVKLink делает пробный запрос к VK-звонку: любой ответ сервера (включая
// редирект на логин) означает, что ссылка жива; сетевая ошибка — ссылка умерла.
func (s *Server) probeVKLink(link string) bool {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(link)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode < 500
}
