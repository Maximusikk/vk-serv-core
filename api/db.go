package main

import (
	"database/sql"
	"fmt"
	"strings"

	_ "modernc.org/sqlite"
)

// DB — обёртка над SQLite (/opt/vkturn/api.db в проде).
type DB struct {
	*sql.DB
}

// OpenDB открывает (создавая при необходимости) базу и инициализирует схему.
func OpenDB(path string) (*DB, error) {
	d, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	// modernc/sqlite не любит много соединений на запись
	d.SetMaxOpenConns(1)
	if err := migrate(d); err != nil {
		d.Close()
		return nil, err
	}
	return &DB{d}, nil
}

func migrate(d *sql.DB) error {
	schema := `
CREATE TABLE IF NOT EXISTS keys (
	id           TEXT PRIMARY KEY,          -- XXXX-XXXX-XXXX-XXXX
	created_at   INTEGER NOT NULL,
	activated_at INTEGER,                   -- NULL если не активирован
	expires_at   INTEGER NOT NULL,          -- unix timestamp
	bytes_limit  INTEGER NOT NULL DEFAULT 0, -- 0 = безлимит
		bytes_used   INTEGER NOT NULL DEFAULT 0,
		local_limit  INTEGER NOT NULL DEFAULT 0, -- 2.3: локальный стоп на ноде (0 = нет), предохранитель при пропаже мастера
		limit80_notified INTEGER NOT NULL DEFAULT 0, -- 2.5: key_limit_80 уже отправлен (один раз на ключ)
		port         INTEGER,
	user_token   TEXT,
	wrap_pass    TEXT,
	notes        TEXT
);
CREATE TABLE IF NOT EXISTS ports (
	port    INTEGER PRIMARY KEY,
	key_id  TEXT,
	active  INTEGER NOT NULL DEFAULT 1,
	state   TEXT,                       -- 1.2: active / down / error (NULL = ещё не проверялся)
	state_checked_at INTEGER            -- 1.2: unix ts последней проверки состояния
);
CREATE INDEX IF NOT EXISTS idx_keys_user_token ON keys(user_token);
CREATE INDEX IF NOT EXISTS idx_keys_port ON keys(port);
-- Последнее прочитанное состояние users/<port>.stats (см. accounting.go)
CREATE TABLE IF NOT EXISTS port_counters (
	port  INTEGER PRIMARY KEY,
	start INTEGER NOT NULL,
	total INTEGER NOT NULL
);
-- Дополнительные VK-ссылки (пул). Основная ссылка по-прежнему VK_LINK в config.txt (см. vklinks.go)
CREATE TABLE IF NOT EXISTS vk_links (
	link       TEXT PRIMARY KEY,
	created_at INTEGER NOT NULL
);
-- Журнал дельт трафика (2.2): каждая дельта, прибавленная к bytes_used.
-- Мастер забирает агрегаты по курсору (GET /admin/usage), записи старше 7 дней чистятся.
CREATE TABLE IF NOT EXISTS usage_log (
	id     INTEGER PRIMARY KEY AUTOINCREMENT,
	key_id TEXT    NOT NULL,
	bytes  INTEGER NOT NULL,
	ts     INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_usage_log_id ON usage_log(id);
CREATE INDEX IF NOT EXISTS idx_usage_log_ts ON usage_log(ts);
`
	if _, err := d.Exec(schema); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	// Инкрементальные миграции для уже существующих баз
	for _, stmt := range []string{
		`ALTER TABLE keys ADD COLUMN device_id TEXT`,         // привязка ключа к устройству
		`ALTER TABLE keys ADD COLUMN external_id TEXT`,       // идемпотентность create (номер заказа бота)
		`ALTER TABLE keys ADD COLUMN revoked_at INTEGER`,     // soft-revoke (C6): NULL = действующий
		`ALTER TABLE keys ADD COLUMN last_unbind_at INTEGER`, // частота unbind (G6)
		`ALTER TABLE keys ADD COLUMN duration_days INTEGER`,  // C5: срок в днях, отсчёт с первой активации (NULL = не ожидает активации)
		`ALTER TABLE keys ADD COLUMN vk_link TEXT`,           // VK-звонок, закреплённый за ключом (пул ссылок); NULL = основная
		`ALTER TABLE ports ADD COLUMN state TEXT`,            // 1.2: active / down / error (NULL = ещё не проверялся)
		`ALTER TABLE ports ADD COLUMN state_checked_at INTEGER`, // 1.2: unix ts последней проверки
		`ALTER TABLE keys ADD COLUMN local_limit INTEGER NOT NULL DEFAULT 0`,      // 2.3: локальный стоп на ноде
		`ALTER TABLE keys ADD COLUMN limit80_notified INTEGER NOT NULL DEFAULT 0`, // 2.5: key_limit_80 отправлен
	} {
		if _, err := d.Exec(stmt); err != nil && !strings.Contains(err.Error(), "duplicate column") {
			return fmt.Errorf("migrate %q: %w", stmt, err)
		}
	}
	// Один external_id = один ключ (повторный вебхук оплаты не создаёт дубликат)
	if _, err := d.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_keys_external_id
		ON keys(external_id) WHERE external_id IS NOT NULL`); err != nil {
		return fmt.Errorf("migrate external_id index: %w", err)
	}
	return nil
}

// GetKeyByKeyID возвращает ключ по его id (XXXX-XXXX-XXXX-XXXX).
func (db *DB) GetKeyByKeyID(keyID string) (*Key, error) {
	row := db.QueryRow(`SELECT id, created_at, activated_at, expires_at, bytes_limit,
		bytes_used, port, user_token, wrap_pass, notes FROM keys WHERE id = ?`, keyID)
	return scanKey(row)
}

// GetKeyByUserToken возвращает ключ по user_token (для /status).
func (db *DB) GetKeyByUserToken(token string) (*Key, error) {
	row := db.QueryRow(`SELECT id, created_at, activated_at, expires_at, bytes_limit,
		bytes_used, port, user_token, wrap_pass, notes FROM keys WHERE user_token = ?`, token)
	return scanKey(row)
}

// GetKeyByPort возвращает ключ, привязанный к порту (для /internal/traffic).
func (db *DB) GetKeyByPort(port int) (*Key, error) {
	row := db.QueryRow(`SELECT id, created_at, activated_at, expires_at, bytes_limit,
		bytes_used, port, user_token, wrap_pass, notes FROM keys WHERE port = ? AND activated_at IS NOT NULL`, port)
	return scanKey(row)
}

func scanKey(row *sql.Row) (*Key, error) {
	var k Key
	var activatedAt, port sql.NullInt64
	var userToken, wrapPassword, notes sql.NullString
	err := row.Scan(&k.ID, &k.CreatedAt, &activatedAt, &k.ExpiresAt, &k.BytesLimit,
		&k.BytesUsed, &port, &userToken, &wrapPassword, &notes)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	k.ActivatedAt = nullInt(activatedAt)
	k.Port = int(nullInt(port))
	k.UserToken = nullStr(userToken)
	k.WrapPassword = nullStr(wrapPassword)
	k.Notes = nullStr(notes)
	return &k, nil
}

// ListKeys возвращает все ключи (для /admin/keys).
func (db *DB) ListKeys() ([]*Key, error) {
	rows, err := db.Query(`SELECT id, created_at, activated_at, expires_at, bytes_limit,
		bytes_used, port, user_token, wrap_pass, notes FROM keys ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*Key
	for rows.Next() {
		var k Key
		var activatedAt, port sql.NullInt64
		var userToken, wrapPassword, notes sql.NullString
		if err := rows.Scan(&k.ID, &k.CreatedAt, &activatedAt, &k.ExpiresAt, &k.BytesLimit,
			&k.BytesUsed, &port, &userToken, &wrapPassword, &notes); err != nil {
			return nil, err
		}
		k.ActivatedAt = nullInt(activatedAt)
		k.Port = int(nullInt(port))
		k.UserToken = nullStr(userToken)
		k.WrapPassword = nullStr(wrapPassword)
		k.Notes = nullStr(notes)
		out = append(out, &k)
	}
	return out, rows.Err()
}

// CreateKey вставляет новый ключ.
func (db *DB) CreateKey(k *Key) error {
	_, err := db.Exec(`INSERT INTO keys (id, created_at, expires_at, bytes_limit, notes)
		VALUES (?, ?, ?, ?, ?)`,
		k.ID, k.CreatedAt, k.ExpiresAt, k.BytesLimit, k.Notes)
	return err
}

// AllocatePort находит свободный порт в диапазоне [start, end] и бронирует его.
func (db *DB) AllocatePort(start, end int) (int, error) {
	rows, err := db.Query(`SELECT port FROM ports WHERE active = 1`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	taken := map[int]bool{}
	for rows.Next() {
		var p int
		if err := rows.Scan(&p); err != nil {
			return 0, err
		}
		taken[p] = true
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	for p := start; p <= end; p++ {
		if !taken[p] {
			if _, err := db.Exec(`INSERT INTO ports (port, active) VALUES (?, 1)`, p); err != nil {
				return 0, err
			}
			return p, nil
		}
	}
	return 0, fmt.Errorf("no free ports in range %d..%d", start, end)
}

// ReleasePort помечает порт свободным.
func (db *DB) ReleasePort(port int) error {
	_, err := db.Exec(`UPDATE ports SET active = 0, key_id = NULL, state = NULL, state_checked_at = NULL WHERE port = ?`, port)
	return err
}

// Состояния порта (1.2). active — юнит/листенер живы; down — не отвечают;
// error — состояние проверить не удалось (ошибка systemctl/сокета).
const (
	PortStateActive = "active"
	PortStateDown   = "down"
	PortStateError  = "error"
)

// SetPortState фиксирует состояние порта и время проверки (1.2).
func (db *DB) SetPortState(port int, state string) error {
	if state != PortStateActive && state != PortStateDown && state != PortStateError {
		return fmt.Errorf("invalid port state %q", state)
	}
	_, err := db.Exec(`UPDATE ports SET state = ?, state_checked_at = strftime('%s','now') WHERE port = ?`, state, port)
	return err
}

// PortState — состояние одного порта (1.2).
type PortState struct {
	Port          int
	KeyID         sql.NullString
	State         sql.NullString
	StateCheckedAt sql.NullInt64
}

// ListPortStates возвращает состояния всех активных портов (1.2, для reconcile и /admin/health).
func (db *DB) ListPortStates() ([]PortState, error) {
	rows, err := db.Query(`SELECT port, key_id, state, state_checked_at FROM ports WHERE active = 1 ORDER BY port`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PortState
	for rows.Next() {
		var ps PortState
		if err := rows.Scan(&ps.Port, &ps.KeyID, &ps.State, &ps.StateCheckedAt); err != nil {
			return nil, err
		}
		out = append(out, ps)
	}
	return out, rows.Err()
}

func nullInt(v sql.NullInt64) int64 {
	if v.Valid {
		return v.Int64
	}
	return 0
}

func nullStr(v sql.NullString) string {
	if v.Valid {
		return v.String
	}
	return ""
}
