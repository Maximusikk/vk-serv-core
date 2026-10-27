package main

// Задача 1.3: Reconcile-цикл — раз в ReconcileInterval (по умолчанию 20 с,
// флаг -reconcile-interval / переменная RECONCILE_INTERVAL) сверяет «что должно
// работать по keys/ports» с реальностью (systemd-юнит vkserv@PORT) и чинит
// расхождения по механике ensureUserUnits (accounting.go) и reprovisionIfDowned
// (admin.go). Результат фиксируется в ports.state (1.2: SetPortState).
//
// Проверка/починка подменяемы коллбеками reconcileCheck/reconcileRepair
// (так же, как provision_test.go подменяет systemctl через PATH) — поэтому
// цикл тестируем без реального systemctl.

import (
	"context"
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

const (
	// defaultReconcileInterval — период reconcile-цикла по умолчанию.
	defaultReconcileInterval = 20 * time.Second
)

// runReconciler — фоновый цикл reconcile (запускается горутиной из main,
// как runTrafficPoller/runExpiryTicker/runNotifyChecker). Паника в одном
// тике не убивает цикл: recover внутри reconcileOnce.
func (s *Server) runReconciler(ctx context.Context) {
	interval := s.cfg.ReconcileInterval
	if interval <= 0 {
		interval = defaultReconcileInterval
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		s.reconcileOnce()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// dbw — обёртка над сырым *sql.DB с методами схемы (SetPortState и др.).
func (s *Server) dbw() *DB { return &DB{s.db} }

// reconcileOnce — один тик: для каждого активного порта сверить юнит с
// реальностью и починить расхождение. Ошибки не прерывают обработку
// остальных портов.
func (s *Server) reconcileOnce() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[reconcile] panic восстановлен: %v", r)
		}
	}()

	states, err := s.dbw().ListPortStates()
	if err != nil {
		log.Printf("[reconcile] list ports: %v", err)
		return
	}
	for _, ps := range states {
		s.reconcileOnePort(ps)
	}
}

// reconcileOnePort — сверка одного порта; recover локален, чтобы паника на
// одном порте не прерывала обработку остальных.
func (s *Server) reconcileOnePort(ps PortState) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[reconcile] порт %d: panic восстановлен: %v", ps.Port, r)
			_ = s.dbw().SetPortState(ps.Port, PortStateError)
		}
	}()
	{
		port := ps.Port
		wasDown := ps.State.Valid && ps.State.String == PortStateDown
		alive, err := s.checkPort(port)
		switch {
		case err != nil:
			// Проверить состояние не удалось (systemctl недоступен/таймаут).
			if serr := s.dbw().SetPortState(port, PortStateError); serr != nil {
				log.Printf("[reconcile] set state error port %d: %v", port, serr)
			}
			log.Printf("[reconcile] порт %d: ошибка проверки: %v", port, err)
		case alive:
			// Всё в порядке — фиксируем и не трогаем; выход из down — событие.
			_ = s.dbw().SetPortState(port, PortStateActive)
			if wasDown {
				s.notifyPortDown(port, true, "порт восстановлен")
			}
		default:
			// Юнит не отвечает — чиним (перезапуск по механике ensureUserUnits).
			rerr := s.repairPort(port)
			if errors.Is(rerr, errPortNotWanted) {
				// Пока шёл тик, порт погасили (revoke/срок/лимит) — поднимать нельзя.
				return
			}
			if rerr != nil {
				_ = s.dbw().SetPortState(port, PortStateDown)
				if !wasDown {
					s.notifyPortDown(port, false, "юнит не отвечает, починка не удалась")
				}
				log.Printf("[reconcile] порт %d: не отвечал, починка не удалась: %v", port, rerr)
				return
			}
			alive2, cerr := s.checkPort(port)
			if cerr == nil && alive2 {
				_ = s.dbw().SetPortState(port, PortStateActive)
				if wasDown {
					s.notifyPortDown(port, true, "порт восстановлен")
				}
				log.Printf("[reconcile] порт %d: юнит не отвечал, перезапущен", port)
			} else {
				_ = s.dbw().SetPortState(port, PortStateDown)
				if !wasDown {
					s.notifyPortDown(port, false, "юнит не отвечает после починки")
				}
				log.Printf("[reconcile] порт %d: юнит не отвечает после починки", port)
			}
		}
	}
}

// errPortNotWanted — порт больше не должен работать (погашен, пока шёл тик).
var errPortNotWanted = errors.New("port no longer wanted")

// portStillWanted — порт активен в ports и его ключ действует: не отозван,
// срок не истёк, лимит не исчерпан. Вызывать под provisionMu.
func (s *Server) portStillWanted(port int) bool {
	var n int
	err := s.db.QueryRow(`
		SELECT COUNT(*) FROM ports p JOIN keys k ON k.port = p.port
		WHERE p.port = ? AND p.active = 1 AND k.activated_at IS NOT NULL
		  AND k.revoked_at IS NULL
		  AND NOT (k.expires_at > 0 AND k.expires_at < ?)
		  AND NOT (k.bytes_limit > 0 AND k.bytes_used >= k.bytes_limit)`,
		port, time.Now().Unix()).Scan(&n)
	return err == nil && n > 0
}

// checkPort — проверка живости порта (подменяемая в тестах).
func (s *Server) checkPort(port int) (bool, error) {
	if s.reconcileCheck != nil {
		return s.reconcileCheck(port)
	}
	return s.portUnitAlive(port)
}

// repairPort — починка порта (подменяемая в тестах).
func (s *Server) repairPort(port int) error {
	if s.reconcileRepair != nil {
		return s.reconcileRepair(port)
	}
	return s.restartPortService(port)
}

// portUnitAlive — жив ли юнит vkserv@PORT. true/false + nil: проверка
// выполнена (юнит active / inactive-failed). err != nil: сам systemctl не
// выполнился (нет бинарника, таймаут) — это PortStateError, а не down.
// Direct-exec фоллбэк (без systemd, G3/Z-16) считается живым, если процесс
// по pidfile ещё работает.
func (s *Server) portUnitAlive(port int) (bool, error) {
	unit := fmt.Sprintf("vkserv@%d", port)
	ctx, cancel := context.WithTimeout(context.Background(), execTimeout10s)
	defer cancel()
	out, err := exec.CommandContext(ctx, "systemctl", "is-active", "--quiet", unit).CombinedOutput()
	if err == nil {
		return true, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		// systemctl ответил: не active (inactive/failed/unknown).
		// Но direct-exec процесс мог пережить юнит — проверяем pidfile.
		if s.directExecAlive(port) {
			return true, nil
		}
		return false, nil
	}
	return false, fmt.Errorf("systemctl is-active %s: %v (%s)", unit, err, strings.TrimSpace(string(out)))
}

// directExecAlive — жив ли direct-exec процесс порта (по pidfile и /proc).
func (s *Server) directExecAlive(port int) bool {
	data, err := os.ReadFile(s.userPidPath(port))
	if err != nil {
		return false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return false
	}
	return cmdlineContains(pid, filepath.Join(s.cfg.InstallDir, "server"))
}

// restartPortService — починка порта по механике ensureUserUnits +
// startUserService: правило iptables → конфиг юзера (если отсутствует) →
// перезапуск юнита vkserv@PORT.
func (s *Server) restartPortService(port int) error {
	// Под provisionMu, как provisionPort/deactivatePort: иначе reconcile может
	// поднять порт, который deactivatePort только что погасил (revoke/срок/лимит).
	s.provisionMu.Lock()
	defer s.provisionMu.Unlock()
	if !s.portStillWanted(port) {
		return errPortNotWanted
	}

	ps := strconv.Itoa(port)

	// 1. iptables: правило теряется после перезагрузки VPS (как в ensureUserUnits).
	if execTimeout(execTimeout10s, "iptables", "-C", "INPUT", "-p", "udp", "--dport", ps, "-j", "ACCEPT") != nil {
		_ = execTimeout(execTimeout10s, "iptables", "-I", "INPUT", "-p", "udp", "--dport", ps, "-j", "ACCEPT")
	}

	// 2. Конфиг юзера: если отсутствует — восстановим из wrap_pass ключа.
	if _, err := os.Stat(s.userConfPath(port)); err != nil {
		var wrapPass string
		if err := s.db.QueryRow(`SELECT wrap_pass FROM keys WHERE port = ? AND revoked_at IS NULL`, port).Scan(&wrapPass); err != nil {
			return fmt.Errorf("wrap_pass for port %d: %w", port, err)
		}
		hy2Pass, _, _, err := s.readMainConfig()
		if err != nil {
			return fmt.Errorf("server config: %w", err)
		}
		if err := s.writeUserConf(port, wrapPass, hy2Pass); err != nil {
			return fmt.Errorf("write user conf: %w", err)
		}
	}

	// 3. Перезапуск юнита: startUserService делает systemctl enable --now,
	// при недоступном systemd уходит в direct exec (тот же путь, что и при
	// обычной активации — поведение не расходится).
	if err := s.startUserService(port); err != nil {
		return fmt.Errorf("start service: %w", err)
	}
	return nil
}
