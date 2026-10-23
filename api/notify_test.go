package main

// Тесты G5 (уведомления продавцу): сбор событий и доставка на webhook.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// G5: ports_low срабатывает при ≥90% ёмкости; постNotification уходит на webhook.
func TestNotifyAlerts(t *testing.T) {
	s, _ := newTestServer(t)
	setupProvisionEnv(t, s)
	s.cfg.MaxActive = 10 // ёмкость 10, ниже — 9 активных = 90% → ports_low
	// VK-ссылка в тестовом config.txt валидна по формату, probe упадёт без сети —
	// поэтому проверяем только наличие ports_low, а не отсутствие остальных.
	for i := 0; i < 9; i++ {
		id := "k-n" + string(rune('a'+i))
		_, err := s.db.Exec(`INSERT INTO keys (id, created_at, activated_at, expires_at, bytes_limit, port)
			VALUES (?, 1, 1, ?, 0, ?)`, id, time.Now().Unix()+1000, 56001+i)
		if err != nil {
			t.Fatal(err)
		}
	}

	var got []notifyPayload
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var p notifyPayload
		json.Unmarshal(body, &p)
		got = append(got, p)
		w.WriteHeader(200)
	}))
	defer hook.Close()
	s.cfg.NotifyURL = hook.URL

	failsA := 0
	alerts := s.collectAlerts(&failsA)
	found := false
	for _, a := range alerts {
		if a.Type == "ports_low" {
			found = true
		}
	}
	if !found {
		t.Fatalf("ports_low not collected: %+v", alerts)
	}

	if !s.postNotify(&http.Client{Timeout: 5 * time.Second}, notifyPayload{Type: "ports_low", Message: "test"}) {
		t.Fatal("postNotify must succeed against test hook")
	}
	if len(got) != 1 || got[0].Type != "ports_low" || got[0].TS == 0 {
		t.Fatalf("webhook payload: %+v", got)
	}
}

// G5: vk_link_dead требует 2 неудачных probe подряд (первый флап игнорируется).
func TestNotifyVKRetries(t *testing.T) {
	s, _ := newTestServer(t)
	setupProvisionEnv(t, s) // config.txt содержит валидную ссылку, probe без сети падает

	fails := 0
	first := s.collectAlerts(&fails)
	if fails != 1 {
		t.Fatalf("first check must count 1 probe failure, got %d", fails)
	}
	for _, a := range first {
		if a.Type == "vk_link_dead" {
			t.Fatal("vk_link_dead must not fire on first failure")
		}
	}
	second := s.collectAlerts(&fails)
	vkDead := false
	for _, a := range second {
		if a.Type == "vk_link_dead" {
			vkDead = true
		}
	}
	if !vkDead {
		t.Fatalf("vk_link_dead must fire on second consecutive failure: %+v", second)
	}
}
