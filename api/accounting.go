package main

// Учёт трафика и обслуживание пользовательских портов.
//
// Каждый vkserv@PORT запускается с -stats-file users/PORT.stats и раз в 10 секунд пишет туда
// "<start_unix> <rx_bytes> <tx_bytes>" — все байты на порту в обе стороны, накопленные с запуска.
// API раз в 30 секунд читает файлы и добавляет прирост к bytes_used ключа.
// Состояние (start, total) хранится в port_counters, поэтому перезапуск API ничего не теряет
// и ничего не считает дважды.

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const trafficPollInterval = 30 * time.Second
const expiryCheckInterval = 60 * time.Second

func (s *Server) statsPath(port int) string {
	return filepath.Join(s.cfg.InstallDir, "users", strconv.Itoa(port)+".stats")
}

// runTrafficPoller — фоновый цикл учёта трафика.
func (s *Server) runTrafficPoller(ctx context.Context) {
	t := time.NewTicker(trafficPollInterval)
	defer t.Stop()
	for {
		s.pollTraffic()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// runExpiryTicker — фоновый цикл гашения ключей с истёкшим сроком.
func (s *Server) runExpiryTicker(ctx context.Context) {
	t := time.NewTicker(expiryCheckInterval)
	defer t.Stop()
	for {
		s.expireOutdatedKeys()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// expireOutdatedKeys гасит порты ключей, у которых истёк expires_at
// (так же, как это делает addTraffic при исчерпании лимита).
func (s *Server) expireOutdatedKeys() {
	rows, err := s.db.Query(`
		SELECT id, port FROM keys
		WHERE port IS NOT NULL AND activated_at IS NOT NULL
		  AND expires_at > 0 AND expires_at < ?`, time.Now().Unix())
	if err != nil {
		log.Printf("[expiry] db: %v", err)
		return
	}
	type expired struct {
		id   string
		port int
	}
	var out []expired
	for rows.Next() {
		var e expired
		if rows.Scan(&e.id, &e.port) == nil {
			out = append(out, e)
		}
	}
	rows.Close()
	for _, e := range out {
		s.deactivatePort(e.port, "expired (key "+e.id+")")
	}
}

func readStatsFile(path string) (start, total int64, ok bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, false
	}
	var rx, tx int64
	if _, err := fmt.Sscanf(strings.TrimSpace(string(data)), "%d %d %d", &start, &rx, &tx); err != nil {
		return 0, 0, false
	}
	return start, rx + tx, true
}

func (s *Server) pollTraffic() {
	rows, err := s.db.Query(`SELECT port FROM keys WHERE port IS NOT NULL AND activated_at IS NOT NULL`)
	if err != nil {
		log.Printf("[traffic] db: %v", err)
		return
	}
	var ports []int
	for rows.Next() {
		var p int
		if rows.Scan(&p) == nil {
			ports = append(ports, p)
		}
	}
	rows.Close()

	for _, port := range ports {
		start, total, ok := readStatsFile(s.statsPath(port))
		if !ok {
			continue
		}
		var prevStart, prevTotal int64
		err := s.db.QueryRow(`SELECT start, total FROM port_counters WHERE port = ?`, port).
			Scan(&prevStart, &prevTotal)

		// Новый процесс (или порт ещё не учитывался) — считаем всё с его запуска
		delta := total
		if err == nil && prevStart == start {
			delta = total - prevTotal
			if delta < 0 {
				delta = total
			}
		}
		if _, err := s.db.Exec(`INSERT INTO port_counters (port, start, total) VALUES (?, ?, ?)
			ON CONFLICT(port) DO UPDATE SET start = excluded.start, total = excluded.total`,
			port, start, total); err != nil {
			log.Printf("[traffic] port %d: %v", port, err)
			continue
		}
		if delta > 0 {
			s.addTraffic(port, delta)
		}
	}
}

// addTraffic добавляет байты к ключу на порту и отключает порт при превышении лимита.
func (s *Server) addTraffic(port int, n int64) {
	res, err := s.db.Exec(`UPDATE keys SET bytes_used = bytes_used + ?
		WHERE port = ? AND activated_at IS NOT NULL`, n, port)
	if err != nil {
		log.Printf("[traffic] port %d: %v", port, err)
		return
	}
	if affected, _ := res.RowsAffected(); affected == 0 {
		return
	}
	var used, limit int64
	if err := s.db.QueryRow(`SELECT bytes_used, bytes_limit FROM keys WHERE port = ?`, port).
		Scan(&used, &limit); err == nil && limit > 0 && used >= limit {
		s.deactivatePort(port, "bytes limit exceeded")
	}
}

// ── Обслуживание юнитов при старте API ─────────────────────────────────────────

const userUnitTemplate = `[Unit]
Description=VKTurn user relay port %i
After=network.target

[Service]
Type=simple
EnvironmentFile={DIR}/users/%i.conf
ExecStart={DIR}/server -listen 0.0.0.0:%i -connect 127.0.0.1:{HY2} -wrap -password ${WRAP_PASS} -stats-file {DIR}/users/%i.stats
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
`

const userUnitPath = "/etc/systemd/system/vkserv@.service"

// serverSupportsStats — у старого бинарника нет -stats-file, с ним юнит упадёт.
func (s *Server) serverSupportsStats() bool {
	ctx, cancel := context.WithTimeout(context.Background(), execTimeout10s)
	defer cancel()
	out, _ := exec.CommandContext(ctx, filepath.Join(s.cfg.InstallDir, "server"), "-h").CombinedOutput()
	return bytes.Contains(out, []byte("stats-file"))
}

func (s *Server) activePorts() []int {
	rows, err := s.db.Query(`SELECT port FROM keys WHERE port IS NOT NULL AND activated_at IS NOT NULL`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []int
	for rows.Next() {
		var p int
		if rows.Scan(&p) == nil {
			out = append(out, p)
		}
	}
	return out
}

// ensureUserUnits приводит шаблон vkserv@.service к актуальному виду (учёт трафика)
// и восстанавливает правила iptables, которые теряются после перезагрузки VPS.
func (s *Server) ensureUserUnits() {
	ports := s.activePorts()

	if s.serverSupportsStats() {
		want := strings.NewReplacer("{DIR}", s.cfg.InstallDir, "{HY2}", strconv.Itoa(s.cfg.Hy2Port)).
			Replace(userUnitTemplate)
		if cur, err := os.ReadFile(userUnitPath); err != nil || string(cur) != want {
			if err := os.WriteFile(userUnitPath, []byte(want), 0644); err != nil {
				log.Printf("[units] write %s: %v", userUnitPath, err)
			} else {
				_ = execTimeout(execTimeout10s, "systemctl", "daemon-reload")
				for _, p := range ports {
					_ = execTimeout(execTimeout10s, "systemctl", "restart", fmt.Sprintf("vkserv@%d", p))
				}
				log.Printf("[units] vkserv@.service обновлён (учёт трафика), перезапущено портов: %d", len(ports))
			}
		}
	} else {
		log.Printf("[units] %s/server без -stats-file — учёт трафика выключен, обнови бинарник", s.cfg.InstallDir)
	}

	for _, p := range ports {
		ps := strconv.Itoa(p)
		if execTimeout(execTimeout10s, "iptables", "-C", "INPUT", "-p", "udp", "--dport", ps, "-j", "ACCEPT") != nil {
			_ = execTimeout(execTimeout10s, "iptables", "-I", "INPUT", "-p", "udp", "--dport", ps, "-j", "ACCEPT")
		}
	}
}
