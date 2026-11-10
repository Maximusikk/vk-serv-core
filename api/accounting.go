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
	"database/sql"
	"errors"
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

// runTrafficPoller — фоновый цикл учёта трафика. Попутно, раз в час, чистит
// usage_log от записей старше 7 дней (2.2).
func (s *Server) runTrafficPoller(ctx context.Context) {
	t := time.NewTicker(trafficPollInterval)
	defer t.Stop()
	var lastClean time.Time
	for {
		s.pollTraffic()
		if lastClean.IsZero() || time.Since(lastClean) >= time.Hour {
			if n, err := s.cleanUsageLog(7 * 24 * time.Hour); err != nil {
				log.Printf("[usage] clean: %v", err)
			} else if n > 0 {
				log.Printf("[usage] чистка usage_log: удалено %d записей старше 7 дней", n)
			}
			lastClean = time.Now()
		}
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
// (так же, как это делает addTraffic при исчерпании лимита), и шлёт key_expired (2.5).
func (s *Server) expireOutdatedKeys() {
	rows, err := s.db.Query(`
		SELECT id, port, IFNULL(external_id,'') FROM keys
		WHERE port IS NOT NULL AND activated_at IS NOT NULL
		  AND expires_at > 0 AND expires_at < ?`, time.Now().Unix())
	if err != nil {
		log.Printf("[expiry] db: %v", err)
		return
	}
	type expired struct {
		id, externalID string
		port           int
	}
	var out []expired
	for rows.Next() {
		var e expired
		if rows.Scan(&e.id, &e.port, &e.externalID) == nil {
			out = append(out, e)
		}
	}
	rows.Close()
	for _, e := range out {
		s.deactivatePort(e.port, "expired (key "+e.id+")")
		s.notifyKeyEvent("key_expired", e.id, e.externalID, e.port)
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

// addTraffic добавляет байты к ключу на порту, пишет дельту в usage_log (2.2)
// и отключает порт при исчерпании лимита — общего (bytes_limit) или локального
// стоп-крана (local_limit, 2.3).
func (s *Server) addTraffic(port int, n int64) {
	// Одна транзакция: прирост + чтение нового состояния + запись дельты в журнал.
	var keyID, externalID string
	var used, limit, localLimit int64
	err := s.tx(func(tx *sql.Tx) error {
		res, err := tx.Exec(`UPDATE keys SET bytes_used = bytes_used + ?
			WHERE port = ? AND activated_at IS NOT NULL`, n, port)
		if err != nil {
			return err
		}
		if affected, _ := res.RowsAffected(); affected == 0 {
			return errNoKeyOnPort // порт уже никому не принадлежит — нечего учитывать
		}
		if err := tx.QueryRow(`SELECT id, IFNULL(external_id,''), bytes_used, bytes_limit, local_limit
			FROM keys WHERE port = ?`, port).
			Scan(&keyID, &externalID, &used, &limit, &localLimit); err != nil {
			return err
		}
		_, err = tx.Exec(`INSERT INTO usage_log (key_id, bytes, ts) VALUES (?, ?, ?)`,
			keyID, n, time.Now().Unix())
		return err
	})
	if err != nil {
		if err != errNoKeyOnPort {
			log.Printf("[traffic] port %d: %v", port, err)
		}
		return
	}

	// 2.5: key_limit_80 — один раз на ключ (флаг limit80_notified).
	if limit > 0 && used*100 >= limit*80 {
		res, err := s.db.Exec(`UPDATE keys SET limit80_notified = 1
			WHERE id = ? AND limit80_notified = 0 AND bytes_limit > 0
			  AND bytes_used*100 >= bytes_limit*80`, keyID)
		if err == nil {
			if affected, _ := res.RowsAffected(); affected > 0 {
				s.notifyKeyEvent("key_limit_80", keyID, externalID, port)
			}
		}
	}

	if (limit > 0 && used >= limit) || (localLimit > 0 && used >= localLimit) {
		reason := "bytes limit exceeded"
		if limit <= 0 {
			reason = "local limit exceeded"
		}
		// Гашение под provisionMu с повторной проверкой ключа (урок из карты).
		s.deactivatePortForLimit(port, keyID, externalID, reason)
	}
}

// errNoKeyOnPort — в addTraffic порт уже не привязан к активированному ключу.
var errNoKeyOnPort = errors.New("no active key on port")

// deactivatePortForLimit гасит порт по лимиту: берёт provisionMu, заново
// проверяет под блокировкой, что на порту всё тот же действующий ключ и лимит
// всё ещё исчерпан (мастер мог успеть снять лимит или сменить владельца), и
// только тогда гасит. Событие key_limit шлётся только при реальном гашении.
func (s *Server) deactivatePortForLimit(port int, keyID, externalID, reason string) {
	s.provisionMu.Lock()
	defer s.provisionMu.Unlock()

	var cur string
	var used, limit, localLimit int64
	if err := s.db.QueryRow(`SELECT id, bytes_used, bytes_limit, local_limit FROM keys
		WHERE port = ? AND activated_at IS NOT NULL AND revoked_at IS NULL`, port).
		Scan(&cur, &used, &limit, &localLimit); err != nil || cur != keyID {
		return // ключ сменился/отозван/не найден — гасить чужой порт нельзя
	}
	if (limit <= 0 || used < limit) && (localLimit <= 0 || used < localLimit) {
		return // лимит уже снят (add_traffic) — порт живой
	}
	s.deactivatePortLocked(port, reason)
	s.notifyKeyEvent("key_limit", keyID, externalID, port)
}

// tx выполняет fn в транзакции: ошибка fn → rollback, иначе commit.
func (s *Server) tx(fn func(tx *sql.Tx) error) error {
	t, err := s.db.Begin()
	if err != nil {
		return err
	}
	if err := fn(t); err != nil {
		_ = t.Rollback()
		return err
	}
	return t.Commit()
}

// notifyKeyEvent — точка вызова вебхуков событий ключа (2.5). Реальная
// реализация назначается в NewServer (notifyKeyEventFn, см. notify.go);
// nil (в старых тестах) — молча пропускаем.
func (s *Server) notifyKeyEvent(event, keyID, externalID string, port int) {
	if s.notifyKeyEventFn != nil {
		s.notifyKeyEventFn(event, keyID, externalID, port)
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
