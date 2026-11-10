package main

// Тесты 1.4: сводка состояний портов в /admin/health и вебхук port_down.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestAdminHealthIncludesPortStates(t *testing.T) {
	db, err := OpenDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()
	s := &Server{db: db.DB, cfg: &Config{InstallDir: t.TempDir()}}

	// Порты: один active, один down, один не проверялся
	for _, p := range []int{56001, 56002, 56003} {
		if _, err := db.AllocatePort(56001, 56010); err != nil {
			t.Fatalf("allocate: %v", err)
		}
		_ = p
	}
	// AllocatePort выдаёт последовательные порты: 56001..56003
	if err := db.SetPortState(56001, PortStateActive); err != nil {
		t.Fatalf("set: %v", err)
	}
	if err := db.SetPortState(56002, PortStateDown); err != nil {
		t.Fatalf("set: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/admin/health", nil)
	w := httptest.NewRecorder()
	s.handleAdminHealth(w, req)
	if w.Code != 200 {
		t.Fatalf("health: HTTP %d: %s", w.Code, w.Body.String())
	}
	var h adminHealth
	if err := json.Unmarshal(w.Body.Bytes(), &h); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if h.Ports == nil {
		t.Fatal("ports block missing")
	}
	if h.Ports.Active != 1 || h.Ports.Down != 1 || h.Ports.Unchecked != 1 {
		t.Fatalf("unexpected counts: %+v", h.Ports)
	}
	if len(h.Ports.DownPorts) != 1 || h.Ports.DownPorts[0] != 56002 {
		t.Fatalf("down_ports: %v", h.Ports.DownPorts)
	}
	if h.Ports.LastCheck <= 0 {
		t.Fatalf("last_check not set: %+v", h.Ports)
	}
}

func TestNotifyPortDown(t *testing.T) {
	events := make(chan notifyPayload, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p notifyPayload
		_ = json.NewDecoder(r.Body).Decode(&p)
		events <- p
		w.WriteHeader(200)
	}))
	defer srv.Close()

	s := &Server{cfg: &Config{NotifyURL: srv.URL}}
	s.sendPortDownWebhook(56002, false, "юнит не отвечает")
	select {
	case p := <-events:
		if p.Type != "port_down" || p.Port != 56002 {
			t.Fatalf("unexpected payload: %+v", p)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("webhook не получен")
	}
}
