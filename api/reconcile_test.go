package main

// Тесты 1.3: reconcile-цикл. Проверка/починка подменяются коллбеками
// (Server.reconcileCheck / reconcileRepair), systemctl не вызывается.

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func newReconcileTestServer(t *testing.T, ports int) *Server {
	t.Helper()
	db, err := OpenDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	s := NewServer(db.DB, &Config{InstallDir: t.TempDir()})
	for i := 0; i < ports; i++ {
		if _, err := db.AllocatePort(56001, 56010); err != nil {
			t.Fatalf("allocate: %v", err)
		}
	}
	return s
}

// Упавший порт чинится: down → repair → active
func TestReconcileRepairsDownedPort(t *testing.T) {
	s := newReconcileTestServer(t, 1)
	var mu sync.Mutex
	repairs := 0
	alive := false
	s.reconcileCheck = func(port int) (bool, error) {
		mu.Lock()
		defer mu.Unlock()
		return alive, nil
	}
	s.reconcileRepair = func(port int) error {
		mu.Lock()
		defer mu.Unlock()
		repairs++
		alive = true // починка поднимает юнит
		return nil
	}

	s.reconcileOnce()

	var states []PortState
	states, err := (&DB{s.db}).ListPortStates()
	if err != nil || len(states) != 1 {
		t.Fatalf("list: %v", err)
	}
	if states[0].State.String != PortStateActive {
		t.Fatalf("want active after repair, got %+v", states[0])
	}
	if repairs != 1 {
		t.Fatalf("want 1 repair, got %d", repairs)
	}
}

// Здоровый порт не трогается, down фиксируется при неудачной починке
func TestReconcileHealthyUntouchedAndDownRecorded(t *testing.T) {
	s := newReconcileTestServer(t, 2)
	mu := sync.Mutex{}
	health := map[int]bool{56001: true, 56002: false}
	s.reconcileCheck = func(port int) (bool, error) {
		mu.Lock()
		defer mu.Unlock()
		return health[port], nil
	}
	s.reconcileRepair = func(port int) error {
		return errors.New("systemctl упал") // починка не помогает
	}

	s.reconcileOnce()

	states, err := (&DB{s.db}).ListPortStates()
	if err != nil || len(states) != 2 {
		t.Fatalf("list: %v", err)
	}
	byPort := map[int]PortState{}
	for _, ps := range states {
		byPort[ps.Port] = ps
	}
	if byPort[56001].State.String != PortStateActive {
		t.Fatalf("56001 want active, got %+v", byPort[56001])
	}
	if byPort[56002].State.String != PortStateDown {
		t.Fatalf("56002 want down, got %+v", byPort[56002])
	}
}

// Один тик обрабатывает все порты; паника в проверке не роняет цикл
func TestReconcileOnceHandlesAllPortsAndRecovers(t *testing.T) {
	s := newReconcileTestServer(t, 3)
	checked := map[int]bool{}
	var mu sync.Mutex
	s.reconcileCheck = func(port int) (bool, error) {
		mu.Lock()
		checked[port] = true
		mu.Unlock()
		if port == 56002 {
			panic("systemctl взорвался")
		}
		return true, nil
	}

	s.reconcileOnce() // recover внутри — не должно упасть

	mu.Lock()
	defer mu.Unlock()
	if len(checked) != 3 {
		t.Fatalf("want 3 ports checked, got %v", checked)
	}
}

// runReconciler выходит по ctx.Done()
func TestReconcilerStopsOnContextCancel(t *testing.T) {
	s := newReconcileTestServer(t, 0) // портов нет — тик мгновенный
	s.reconcileCheck = func(port int) (bool, error) { return true, nil }
	s.cfg.ReconcileInterval = 10 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		s.runReconciler(ctx)
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runReconciler не вышел по ctx")
	}
}

// Переход в down и восстановление шлют вебхуки port_down / port_recovered (1.4)
func TestReconcileNotifiesOnDownTransition(t *testing.T) {
	s := newReconcileTestServer(t, 1)
	events := make(chan notifyPayload, 4)
	s.notifyPortDown = func(port int, recovered bool, reason string) {
		p := notifyPayload{Port: port, Message: reason}
		if recovered {
			p.Type = "port_recovered"
		} else {
			p.Type = "port_down"
		}
		events <- p
	}

	states := map[int]bool{56001: false} // тик 1: down
	s.reconcileCheck = func(port int) (bool, error) { return states[port], nil }
	s.reconcileRepair = func(port int) error { return errors.New("не чинится") }
	s.reconcileOnce()
	select {
	case p := <-events:
		if p.Type != "port_down" || p.Port != 56001 {
			t.Fatalf("want port_down/56001, got %+v", p)
		}
	default:
		t.Fatal("нет вебхука port_down на первом тике")
	}

	// тик 2: всё ещё down — повторного вебхука быть не должно
	s.reconcileOnce()
	select {
	case p := <-events:
		t.Fatalf("повторный вебхук без перехода: %+v", p)
	default:
	}

	// тик 3: восстановился — port_recovered
	states[56001] = true
	s.reconcileCheck = func(port int) (bool, error) { return true, nil }
	s.reconcileOnce()
	select {
	case p := <-events:
		if p.Type != "port_recovered" || p.Port != 56001 {
			t.Fatalf("want port_recovered/56001, got %+v", p)
		}
	default:
		t.Fatal("нет вебхука port_recovered")
	}
}
