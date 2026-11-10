package main

// Тест 1.2: колонки ports.state / state_checked_at — миграция старой базы,
// установка и чтение состояния порта.

import (
	"path/filepath"
	"testing"
)

func TestPortStateMigrationAndLifecycle(t *testing.T) {
	// Свежая база: схема сразу с колонками
	db, err := OpenDB(filepath.Join(t.TempDir(), "fresh.db"))
	if err != nil {
		t.Fatalf("open fresh: %v", err)
	}
	defer db.Close()

	if _, err := db.AllocatePort(56001, 56010); err != nil {
		t.Fatalf("allocate: %v", err)
	}
	if err := db.SetPortState(56001, PortStateActive); err != nil {
		t.Fatalf("set state: %v", err)
	}
	states, err := db.ListPortStates()
	if err != nil || len(states) != 1 {
		t.Fatalf("list states: %v (%d)", err, len(states))
	}
	if states[0].Port != 56001 || !states[0].State.Valid || states[0].State.String != PortStateActive {
		t.Fatalf("unexpected state: %+v", states[0])
	}
	if !states[0].StateCheckedAt.Valid || states[0].StateCheckedAt.Int64 <= 0 {
		t.Fatalf("state_checked_at not set: %+v", states[0])
	}

	// Недопустимое состояние — ошибка
	if err := db.SetPortState(56001, "bogus"); err == nil {
		t.Fatal("expected error for bogus state")
	}

	// ReleasePort сбрасывает состояние
	if err := db.ReleasePort(56001); err != nil {
		t.Fatalf("release: %v", err)
	}
	states, _ = db.ListPortStates()
	if len(states) != 0 {
		t.Fatalf("released port still listed: %+v", states)
	}
}

func TestPortStateMigrationFromOldSchema(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "old.db")

	// База старой схемы (без state/state_checked_at), как до 1.2
	old, err := OpenDB(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	// Эмулируем старую базу: пересоздаём таблицу ports без новых колонок
	old.Exec(`DROP TABLE ports`)
	old.Exec(`CREATE TABLE ports (port INTEGER PRIMARY KEY, key_id TEXT, active INTEGER NOT NULL DEFAULT 1)`)
	old.Exec(`INSERT INTO ports (port, key_id, active) VALUES (56001, 'k1', 1)`)
	old.Close()

	db, err := OpenDB(path)
	if err != nil {
		t.Fatalf("reopen old db: %v", err)
	}
	defer db.Close()

	if err := db.SetPortState(56001, PortStateDown); err != nil {
		t.Fatalf("set state on migrated db: %v", err)
	}
	states, err := db.ListPortStates()
	if err != nil || len(states) != 1 {
		t.Fatalf("list: %v (%d)", err, len(states))
	}
	if states[0].State.String != PortStateDown {
		t.Fatalf("want down, got %+v", states[0])
	}
}
