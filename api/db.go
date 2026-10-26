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
	port         INTEGER,
	user_token   TEXT,
	wrap_pass    TEXT,
	notes        TEXT
);
CREATE TABLE IF NOT EXISTS ports (
	port    INTEGER PRIMARY KEY,
	key_id  TEXT,
	active  INTEGER NOT NULL DEFAULT 1
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
	_, err := db.Exec(`UPDATE ports SET active = 0, key_id = NULL WHERE port = ?`, port)
	return err
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
