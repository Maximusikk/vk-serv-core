package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ── POST /internal/traffic ────────────────────────────────────────────────────

type trafficRequest struct {
	Port  int   `json:"port"`
	Bytes int64 `json:"bytes"`
}

// handleInternalTraffic — POST /internal/traffic
// УСТАРЕЛО: раньше вызывалось tracker.sh (iptables, только входящий трафик).
// Теперь учёт ведёт accounting.go по данным самого server. Запросы старого cron
// принимаются и игнорируются, чтобы не считать трафик дважды.
func (s *Server) handleInternalTraffic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Только с localhost (tracker.sh) — даже если API слушает 0.0.0.0
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err != nil || !net.ParseIP(host).IsLoopback() {
		jsonError(w, "forbidden", http.StatusForbidden)
		return
	}

	// Проверяем внутренний секрет
	if !secretEqual(r.Header.Get("X-Internal"), s.cfg.InternalSecret) {
		jsonError(w, "forbidden", http.StatusForbidden)
		return
	}

	var req trafficRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Port <= 0 || req.Bytes < 0 {
		jsonError(w, "invalid port or bytes", http.StatusBadRequest)
		return
	}

	jsonOK(w, map[string]string{"status": "ignored", "reason": "deprecated: traffic is read from server stats files"})
}

// deactivatePort останавливает vkserv на порту и закрывает iptables правило.
// Под сериализацией provisionMu (V3): порт может переиспользоваться следующим
// владельцем сразу после UPDATE ports/keys — без мьютекса гашение старого порта
// способно задеть живой vkserv нового юзера, а его трафик — попасть чужому.
// deactivatePort не вызывается из кода, уже держащего provisionMu
// (provisionPort при откате делает очистку инлайн) — дедлока нет.
func (s *Server) deactivatePort(port int, reason string) {
	s.provisionMu.Lock()
	defer s.provisionMu.Unlock()

	unit := fmt.Sprintf("vkserv@%d", port)

	// Останавливаем и отключаем systemd юнит
	_ = execTimeout(execTimeout10s, "systemctl", "stop", unit)
	_ = execTimeout(execTimeout10s, "systemctl", "disable", unit)

	// G3/Z-16: если порт поднимался direct-exec фолбэком (без systemd),
	// systemctl его не гасил — добиваем по pidfile.
	s.stopDirectProcess(port)

	// Закрываем iptables
	_ = execTimeout(execTimeout10s, "iptables", "-D", "INPUT", "-p", "udp",
		"--dport", strconv.Itoa(port), "-j", "ACCEPT")

	// Помечаем порт неактивным в БД
	_, _ = s.db.Exec(`UPDATE ports SET active = 0 WHERE port = ?`, port)
	_, _ = s.db.Exec(`UPDATE keys SET port = NULL WHERE port = ?`, port)

	// Счётчики трафика этого порта — чтобы следующий владелец порта начал с нуля
	_, _ = s.db.Exec(`DELETE FROM port_counters WHERE port = ?`, port)
	_ = os.Remove(s.statsPath(port))
	// Конфиг юзера содержит WRAP_PASS и HY2_PASS — не оставляем его на диске
	_ = os.Remove(s.userConfPath(port))

	fmt.Printf("[api] port %d deactivated: %s\n", port, reason)
}

// stopDirectProcess гасит процесс, запущенный direct-exec фолбэком (G3/Z-16).
// При systemd-запуске pidfile отсутствует — вызов ничего не делает.
// Порядок: чтение pid → kill (после проверки, что это наш server) → удаление pidfile.
func (s *Server) stopDirectProcess(port int) {
	data, err := os.ReadFile(s.userPidPath(port))
	_ = os.Remove(s.userPidPath(port))
	if err != nil {
		return
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 {
		return
	}
	killPortProcess(pid, filepath.Join(s.cfg.InstallDir, "server"))
}
