package main

// Reconcile не должен поднимать порт, который погасили между тиком и починкой
// (revoke / истёк срок / исчерпан лимит): иначе отозванный ключ снова работает.

import (
	"errors"
	"testing"
	"time"
)

func TestPortStillWanted(t *testing.T) {
	now := time.Now().Unix()
	cases := []struct {
		name      string
		expires   int64
		limit     int64
		used      int64
		revokedAt any
		want      bool
	}{
		{"действующий", now + 3600, 0, 0, nil, true},
		{"без срока", 0, 0, 0, nil, true},
		{"отозван", now + 3600, 0, 0, now, false},
		{"истёк срок", now - 10, 0, 0, nil, false},
		{"исчерпан лимит", now + 3600, 100, 100, nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := newReconcileTestServer(t, 1)
			if _, err := s.db.Exec(`INSERT INTO keys
				(id, created_at, activated_at, expires_at, bytes_limit, bytes_used, port, revoked_at)
				VALUES ('k1', ?, ?, ?, ?, ?, 56001, ?)`,
				now, now, c.expires, c.limit, c.used, c.revokedAt); err != nil {
				t.Fatalf("insert key: %v", err)
			}
			if got := s.portStillWanted(56001); got != c.want {
				t.Fatalf("portStillWanted = %v, want %v", got, c.want)
			}
			if !c.want {
				if err := s.restartPortService(56001); !errors.Is(err, errPortNotWanted) {
					t.Fatalf("restartPortService: want errPortNotWanted, got %v", err)
				}
			}
		})
	}
}

// Погашенный порт (ports.active = 0) тоже не поднимается.
func TestPortStillWantedInactivePort(t *testing.T) {
	s := newReconcileTestServer(t, 1)
	now := time.Now().Unix()
	if _, err := s.db.Exec(`INSERT INTO keys (id, created_at, activated_at, expires_at, port)
		VALUES ('k1', ?, ?, ?, 56001)`, now, now, now+3600); err != nil {
		t.Fatalf("insert key: %v", err)
	}
	if _, err := s.db.Exec(`UPDATE ports SET active = 0 WHERE port = 56001`); err != nil {
		t.Fatal(err)
	}
	if s.portStillWanted(56001) {
		t.Fatal("inactive port must not be wanted")
	}
}
