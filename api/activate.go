package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ── Запрос активации ──────────────────────────────────────────────────────────

type activateRequest struct {
	Key      string `json:"key"`
	VKLink   string `json:"vk_link"`   // опционально: по умолчанию берётся VK_LINK из config.txt
	DeviceID string `json:"device_id"` // ключ привязывается к первому устройству
}

type activateResponse struct {
	Token      string `json:"token"`
	Config     string `json:"config"`
	ExpiresAt  int64  `json:"expires_at"`
	BytesLimit int64  `json:"bytes_limit"`
}

// handleActivate — POST /activate
func (s *Server) handleActivate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req activateRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	// Ключи хранятся строчным hex, а клиент шлёт ЗАГЛАВНЫМИ — нормализуем.
	req.Key = strings.ToLower(strings.TrimSpace(req.Key))
	req.VKLink = strings.TrimSpace(req.VKLink)
	req.DeviceID = strings.TrimSpace(req.DeviceID)

	if req.Key == "" {
		jsonError(w, "key is required", http.StatusBadRequest)
		return
	}
	if req.DeviceID == "" || len(req.DeviceID) > 128 {
		jsonError(w, "Обнови приложение VKTurn — эта версия не поддерживается", http.StatusBadRequest)
		return
	}
	// VK-звонок — забота сервера: пул ссылок (VK_LINK из config.txt + таблица vk_links, см. vklinks.go).
	// Ссылка от клиента — только запасной вариант для старых установок без VK_LINK.
	fallbackVK := req.VKLink
	if len(s.vkPool()) == 0 && (!strings.Contains(fallbackVK, "vk.") || !strings.Contains(fallbackVK, "call/join/")) {
		jsonError(w, "VK ссылка не настроена на сервере (запусти /opt/vkturn/update-vk.sh)", http.StatusServiceUnavailable)
		return
	}

	// ── Найти ключ в БД ───────────────────────────────────────────────────────
	row := s.db.QueryRow(`
		SELECT id, activated_at, expires_at, bytes_limit, bytes_used, port, user_token, device_id, revoked_at
		FROM keys WHERE id = ?`, req.Key)

	var (
		id            string
		activatedAt   *int64
		expiresAt     int64
		bytesLimit    int64
		bytesUsed     int64
		existingPort  *int
		existingToken *string
		boundDevice   *string
		revokedAt     *int64
	)
	if err := row.Scan(&id, &activatedAt, &expiresAt, &bytesLimit, &bytesUsed, &existingPort, &existingToken, &boundDevice, &revokedAt); err != nil {
		jsonErrorCode(w, "Ключ не найден", "key_not_found", http.StatusNotFound)
		return
	}

	// Отозванный ключ не активируется, пока продавец не выдаст новый (soft-revoke, C6)
	if revokedAt != nil {
		jsonErrorCode(w, "Ключ отозван — обратись к продавцу", "revoked", http.StatusForbidden)
		return
	}

	// Проверяем срок действия
	if expiresAt > 0 && time.Now().Unix() > expiresAt {
		jsonErrorCode(w, "Срок действия ключа истёк", "expired", http.StatusForbidden)
		return
	}
	// Лимит трафика: иначе после отключения по лимиту ключ активировался бы заново
	if bytesLimit > 0 && bytesUsed >= bytesLimit {
		jsonErrorCode(w, "Лимит трафика по ключу исчерпан", "limit_exhausted", http.StatusForbidden)
		return
	}
	// Один ключ — одно устройство. Отвязать можно в админке (POST /admin/keys/{id}/unbind).
	if boundDevice != nil && *boundDevice != "" && *boundDevice != req.DeviceID {
		jsonErrorCode(w, "Ключ уже активирован на другом устройстве", "bound_other_device", http.StatusForbidden)
		return
	}
	if boundDevice == nil || *boundDevice == "" {
		// Первое устройство (или ключ, активированный до появления привязки) — закрепляем.
		// Атомарно: если два устройства активируют одновременно, выиграет одно.
		res, err := s.db.Exec(`UPDATE keys SET device_id = ?
			WHERE id = ? AND (device_id IS NULL OR device_id = '')`, req.DeviceID, req.Key)
		if err != nil {
			jsonError(w, "db error: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if n, _ := res.RowsAffected(); n == 0 {
			var winner string
			_ = s.db.QueryRow(`SELECT COALESCE(device_id, '') FROM keys WHERE id = ?`, req.Key).Scan(&winner)
			if winner != req.DeviceID {
				jsonErrorCode(w, "Ключ уже активирован на другом устройстве", "bound_other_device", http.StatusForbidden)
				return
			}
		}
	}

	// Ссылка на VK-звонок: закреплена за ключом, новым ключам достаётся наименее загруженная
	vkLink := s.assignVKLink(req.Key, fallbackVK)

	// Уже активирован — отдаём конфиг повторно (переактивация тем же устройством)
	if activatedAt != nil && existingPort != nil && existingToken != nil {
		config, err := s.buildVkturnLink(req.Key, *existingPort, vkLink)
		if err != nil {
			jsonError(w, "failed to build config: "+err.Error(), http.StatusInternalServerError)
			return
		}
		jsonOK(w, activateResponse{
			Token:      *existingToken,
			Config:     config,
			ExpiresAt:  expiresAt,
			BytesLimit: bytesLimit,
		})
		return
	}

	// ── Выдаём порт ───────────────────────────────────────────────────────────
	// Ёмкость сервера (G3): -max-active ограничивает число живых vkserv@.
	if s.cfg.MaxActive > 0 {
		var active int
		if err := s.db.QueryRow(`SELECT COUNT(*) FROM keys
			WHERE port IS NOT NULL AND activated_at IS NOT NULL`).Scan(&active); err != nil {
			jsonError(w, "db error: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if active >= s.cfg.MaxActive {
			jsonError(w, "Сервер заполнен — обратись к продавцу, это временно", http.StatusServiceUnavailable)
			return
		}
	}
	prov, err := s.provisionPort(req.Key, false)
	if err != nil {
		if strings.Contains(err.Error(), "no free ports") {
			jsonError(w, err.Error(), http.StatusServiceUnavailable)
		} else {
			jsonError(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}
	// C5: срок мог быть выставлен именно сейчас (первая активация) — отдаём актуальный expires_at.
	_ = s.db.QueryRow(`SELECT expires_at FROM keys WHERE id = ?`, req.Key).Scan(&expiresAt)

	hy2Pass, serverIP, _, err := s.readMainConfig()
	if err != nil {
		jsonError(w, "server config error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// ── Генерируем vkturn:// ─────────────────────────────────────────────────
	config, err := buildVkturnLinkRaw(serverIP, prov.Port, vkLink, prov.WrapPass, hy2Pass, s.cfg.TLSPin)
	if err != nil {
		jsonError(w, "failed to build config", http.StatusInternalServerError)
		return
	}

	jsonOK(w, activateResponse{
		Token:      prov.UserToken,
		Config:     config,
		ExpiresAt:  expiresAt,
		BytesLimit: bytesLimit,
	})

	// 2.5: ключ успешно активирован, порт выдан — уведомляем продавца.
	var extID string
	_ = s.db.QueryRow(`SELECT IFNULL(external_id,'') FROM keys WHERE id = ?`, req.Key).Scan(&extID)
	s.notifyKeyEvent("key_activated", req.Key, extID, prov.Port)
}

// ── Выдача порта ──────────────────────────────────────────────────────────────

type provisionResult struct {
	Port      int
	WrapPass  string
	UserToken string
}

// provisionPort выдаёт ключу порт: allocate → конфиг юзера → запуск vkserv@ →
// iptables → UPDATE keys/ports. Одна реализация для /activate и для переподъёма
// после продления/докупки (admin.go), чтобы поведение не расходилось.
// Под сериализацией provisionMu — параллельные вызовы не должны получить один порт.
// keepToken: true — сохранить прежний user_token (переподъём после продления),
// false — выдать новый (первая активация).
func (s *Server) provisionPort(keyID string, keepToken bool) (*provisionResult, error) {
	s.provisionMu.Lock()
	defer s.provisionMu.Unlock()

	// Повторная проверка под мьютексом: два одновременных запроса одного ключа
	// (двойной тап, ретрай клиента, /activate + PATCH) не должны выдать ему два порта —
	// первый vkserv@ остался бы работать «сиротой» без учёта и без гашения.
	var curPort *int
	var curWrap, curToken *string
	if err := s.db.QueryRow(`SELECT port, wrap_pass, user_token FROM keys WHERE id = ?`, keyID).
		Scan(&curPort, &curWrap, &curToken); err == nil &&
		curPort != nil && curWrap != nil && *curWrap != "" && curToken != nil && *curToken != "" {
		return &provisionResult{Port: *curPort, WrapPass: *curWrap, UserToken: *curToken}, nil
	}

	port, err := s.allocatePort()
	if err != nil {
		return nil, err
	}

	wrapPass, err := randomHex(16)
	if err != nil {
		return nil, fmt.Errorf("crypto error: %w", err)
	}
	userToken := ""
	if keepToken {
		_ = s.db.QueryRow(`SELECT user_token FROM keys WHERE id = ?`, keyID).Scan(&userToken)
	}
	if userToken == "" {
		userToken, err = randomUUID()
		if err != nil {
			return nil, fmt.Errorf("crypto error: %w", err)
		}
	}

	hy2Pass, _, _, err := s.readMainConfig()
	if err != nil {
		return nil, fmt.Errorf("server config error: %w", err)
	}

	if err := s.writeUserConf(port, wrapPass, hy2Pass); err != nil {
		return nil, fmt.Errorf("failed to write user config: %w", err)
	}
	if err := s.startUserService(port); err != nil {
		// Убираем конфиг если сервис не стартовал
		_ = os.Remove(s.userConfPath(port))
		return nil, fmt.Errorf("failed to start service: %w", err)
	}

	// ── Открываем порт в iptables ─────────────────────────────────────────────
	_ = execTimeout(execTimeout10s, "iptables", "-I", "INPUT", "-p", "udp",
		"--dport", strconv.Itoa(port), "-j", "ACCEPT")

	// ── Сохраняем в БД (activated_at при переподъёме не трогаем) ──────────────
	// C5: при ПЕРВОЙ активации ключа с duration_days срок начинает течь именно сейчас.
	// В SQLite выражения SET читают СТАРЫЕ значения строки, поэтому activated_at IS NULL в CASE верно.
	// Срок выставляется только после успешного запуска порта: отказ «сервер заполнен»
	// или ошибка systemd не сжигают дни, за которые клиент заплатил.
	now := time.Now().Unix()
	if _, err := s.db.Exec(`
		UPDATE keys SET
			expires_at   = CASE WHEN activated_at IS NULL AND COALESCE(duration_days, 0) > 0 AND expires_at = 0
			                    THEN ? + duration_days * 86400 ELSE expires_at END,
			activated_at = COALESCE(activated_at, ?),
			port         = ?,
			user_token   = ?,
			wrap_pass    = ?
		WHERE id = ?`,
		now, now, port, userToken, wrapPass, keyID); err != nil {
		// Откат: останавливаем сервис (и direct-exec процесс, если запускали),
		// закрываем порт
		_ = execTimeout(execTimeout10s, "systemctl", "stop", fmt.Sprintf("vkserv@%d", port))
		s.stopDirectProcess(port)
		_ = execTimeout(execTimeout10s, "iptables", "-D", "INPUT", "-p", "udp",
			"--dport", strconv.Itoa(port), "-j", "ACCEPT")
		_ = os.Remove(s.userConfPath(port))
		return nil, fmt.Errorf("db error: %w", err)
	}

	// Порт мог быть занят раньше (строка с active=0) — обновляем, а не тихо падаем на PRIMARY KEY
	_, _ = s.db.Exec(`INSERT INTO ports (port, key_id, active) VALUES (?, ?, 1)
		ON CONFLICT(port) DO UPDATE SET key_id = excluded.key_id, active = 1`, port, keyID)

	return &provisionResult{Port: port, WrapPass: wrapPass, UserToken: userToken}, nil
}

// ── Вспомогательные ──────────────────────────────────────────────────────────

// allocatePort находит первый свободный порт в диапазоне PORT_START..PORT_END.
func (s *Server) allocatePort() (int, error) {
	var usedPorts = make(map[int]bool)
	rows, err := s.db.Query(`SELECT port FROM ports WHERE active = 1 AND port IS NOT NULL`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var p int
			if rows.Scan(&p) == nil {
				usedPorts[p] = true
			}
		}
	}
	for p := s.cfg.PortStart; p <= s.cfg.PortEnd; p++ {
		if !usedPorts[p] {
			return p, nil
		}
	}
	return 0, fmt.Errorf("all ports in use (%d-%d)", s.cfg.PortStart, s.cfg.PortEnd)
}

// userConfPath возвращает путь к конфигу юзера.
func (s *Server) userConfPath(port int) string {
	return filepath.Join(s.cfg.InstallDir, "users", strconv.Itoa(port)+".conf")
}

// userPidPath возвращает путь к pidfile direct-exec фолбэка (G3/Z-16).
// При systemd-запуске файл не создаётся — юнит гасится systemctl.
func (s *Server) userPidPath(port int) string {
	return filepath.Join(s.cfg.InstallDir, "users", strconv.Itoa(port)+".pid")
}

// writeUserConf записывает /opt/vkturn/users/{port}.conf.
func (s *Server) writeUserConf(port int, wrapPass, hy2Pass string) error {
	dir := filepath.Join(s.cfg.InstallDir, "users")
	if err := os.MkdirAll(dir, 0750); err != nil {
		return err
	}
	content := fmt.Sprintf("WRAP_PASS=%s\nHY2_PASS=%s\nPORT=%d\n", wrapPass, hy2Pass, port)
	return os.WriteFile(s.userConfPath(port), []byte(content), 0640)
}

// startUserService запускает systemd юнит vkserv@PORT.
func (s *Server) startUserService(port int) error {
	unit := fmt.Sprintf("vkserv@%d", port)
	if err := execTimeout(execTimeout10s, "systemctl", "enable", "--now", unit); err != nil {
		// Пробуем через direct exec как фоллбэк (без systemd, например в Docker)
		confPath := s.userConfPath(port)
		wrapPass, _, _ := parseUserConf(confPath)
		args := []string{
			"-listen", fmt.Sprintf("0.0.0.0:%d", port),
			"-connect", fmt.Sprintf("127.0.0.1:%d", s.cfg.Hy2Port),
			"-wrap",
			"-password", wrapPass,
		}
		if s.serverSupportsStats() {
			args = append(args, "-stats-file", s.statsPath(port))
		}
		cmd := exec.Command(filepath.Join(s.cfg.InstallDir, "server"), args...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			return fmt.Errorf("direct exec failed: %w", err)
		}
		// G3/Z-16: процесс вне systemd — systemctl его не погасит. Пишем pidfile,
		// по которому deactivatePort/откат provisionPort убьют процесс.
		if werr := os.WriteFile(s.userPidPath(port), []byte(strconv.Itoa(cmd.Process.Pid)+"\n"), 0640); werr != nil {
			_ = cmd.Process.Kill()
			return fmt.Errorf("failed to write pidfile: %w", werr)
		}
		go func() { _ = cmd.Wait() }() // пожинаем процесс — не оставляем зомби
		return nil
	}
	return nil
}

// readMainConfig читает /opt/vkturn/config.txt.
func (s *Server) readMainConfig() (hy2Pass, serverIP, vkLink string, err error) {
	data, err := os.ReadFile(filepath.Join(s.cfg.InstallDir, "config.txt"))
	if err != nil {
		return "", "", "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "HY2_PASS=") {
			hy2Pass = strings.TrimPrefix(line, "HY2_PASS=")
		}
		if strings.HasPrefix(line, "SERVER_IP=") {
			serverIP = strings.TrimPrefix(line, "SERVER_IP=")
		}
		if strings.HasPrefix(line, "VK_LINK=") {
			vkLink = strings.TrimPrefix(line, "VK_LINK=")
		}
	}
	if hy2Pass == "" || serverIP == "" {
		return "", "", "", fmt.Errorf("HY2_PASS or SERVER_IP not found in config.txt")
	}
	return hy2Pass, serverIP, vkLink, nil
}

// buildVkturnLink генерирует vkturn:// для уже активированного юзера
// (берёт wrap_pass из БД).
func (s *Server) buildVkturnLink(keyID string, port int, vkLink string) (string, error) {
	row := s.db.QueryRow(`SELECT wrap_pass FROM keys WHERE id = ?`, keyID)
	var wrapPass string
	if err := row.Scan(&wrapPass); err != nil || wrapPass == "" {
		return "", fmt.Errorf("wrap_pass not found")
	}
	hy2Pass, serverIP, _, err := s.readMainConfig()
	if err != nil {
		return "", err
	}
	return buildVkturnLinkRaw(serverIP, port, vkLink, wrapPass, hy2Pass, s.cfg.TLSPin)
}

// buildVkturnLinkRaw собирает vkturn://v1/<base64json>.
// pin (S3) — SPKI-пин API-сервера: кладётся в payload, чтобы клиент проверил
// сертификат до отправки ключа (контракт §1). Пустой pin поле не добавляет.
func buildVkturnLinkRaw(serverIP string, port int, vkLink, wrapPass, hy2Pass, pin string) (string, error) {
	hy2Profile := fmt.Sprintf(
		"hysteria2://%s@%s:%d?sni=%s&insecure=1#VKTurn",
		hy2Pass, serverIP, 10443, serverIP, // hy2 всегда на 10443
	)
	cfg := map[string]string{
		"n":       "VKTurn",
		"peer":    fmt.Sprintf("%s:%d", serverIP, port),
		"vk":      vkLink,
		"pwd":     wrapPass,
		"profile": hy2Profile,
	}
	if pin != "" {
		cfg["pin"] = pin
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		return "", err
	}
	b64 := base64.RawURLEncoding.EncodeToString(raw)
	return "vkturn://v1/" + b64, nil
}

// parseUserConf читает WRAP_PASS из .conf файла.
func parseUserConf(path string) (wrapPass, hy2Pass string, port int) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "WRAP_PASS=") {
			wrapPass = strings.TrimPrefix(line, "WRAP_PASS=")
		}
		if strings.HasPrefix(line, "HY2_PASS=") {
			hy2Pass = strings.TrimPrefix(line, "HY2_PASS=")
		}
		if strings.HasPrefix(line, "PORT=") {
			port, _ = strconv.Atoi(strings.TrimPrefix(line, "PORT="))
		}
	}
	return
}

// ── Утилиты ───────────────────────────────────────────────────────────────────

// execTimeout выполняет команду с таймаутом (B6) — зависший systemctl/iptables
// не должен держать хендлер (и provisionMu) вечно.
func execTimeout(timeout time.Duration, name string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).Run()
}

const execTimeout10s = 10 * time.Second

// maxBodyBytes — лимит тела JSON-запросов (B4).
const maxBodyBytes = 16 << 10

// decodeJSON читает JSON-тело с ограничением размера; при ошибке уже ответила 400.
func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return false
	}
	return true
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func randomUUID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}

func jsonOK(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// jsonErrorCode — как jsonError, плюс машинный код причины ("code").
// Клиент по нему выбирает UI-состояние (истёк / лимит / другое устройство),
// не разбирая русский текст. Поле "error" остаётся — старые клиенты работают как раньше.
func jsonErrorCode(w http.ResponseWriter, msg, errCode string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg, "code": errCode})
}
