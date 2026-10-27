package main

// Уведомления продавцу (G5): фоновый цикл, который раз в notifyCheckInterval
// проверяет здоровье сервера и POST-ает JSON на -notify-url / NOTIFY_URL
// (webhook бота продавца, Bot API Telegram и т.п. — любой URL, принимающий POST).
//
// События:
//   vk_link_dead  — VK-ссылка не отвечает (2 проверки подряд, защита от флапа)
//   disk_low      — свободное место на разделе установки < 500 МБ
//   ports_low     — занято ≥ 90% ёмкости портов (max_active или диапазон портов)
//
// Чтобы не заспамить продавца: одно и то же событие отправляется не чаще,
// чем раз в notifyRepeatAfter (6 ч), пока остаётся активным.

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"syscall"
	"time"
)

const (
	notifyCheckInterval = 5 * time.Minute
	notifyRepeatAfter   = 6 * time.Hour
	notifyVKRetries     = 2 // подряд неудачных probe, прежде чем считать ссылку мёртвой
	notifyDiskMinMB     = 500
	notifyPortsPct      = 90
)

type notifyPayload struct {
	Type    string `json:"type"` // vk_link_dead | disk_low | ports_low | port_down | port_recovered
	Message string `json:"message"`
	TS      int64  `json:"ts"`
	Version string `json:"api_version"`
	Port    int    `json:"port,omitempty"` // port_down / port_recovered (1.4)
}

// runNotifyChecker — фоновый цикл уведомлений; молчит, если NotifyURL не задан.
func (s *Server) runNotifyChecker(ctx context.Context) {
	if s.cfg.NotifyURL == "" {
		return
	}
	lastSent := map[string]time.Time{}
	vkFails := 0
	client := &http.Client{Timeout: 10 * time.Second}

	t := time.NewTicker(notifyCheckInterval)
	defer t.Stop()
	for {
		for _, a := range s.collectAlerts(&vkFails) {
			if last, ok := lastSent[a.Type]; ok && time.Since(last) < notifyRepeatAfter {
				continue
			}
			if s.postNotify(client, a) {
				lastSent[a.Type] = time.Now()
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// collectAlerts возвращает активные события (vk_link_dead требует 2 неудач подряд).
func (s *Server) collectAlerts(vkFails *int) []notifyPayload {
	var alerts []notifyPayload

	if _, _, link, err := s.readMainConfig(); err == nil && validVKLink(link) {
		if s.probeVKLink(link) {
			*vkFails = 0
		} else {
			*vkFails++
			if *vkFails >= notifyVKRetries {
				alerts = append(alerts, notifyPayload{
					Type:    "vk_link_dead",
					Message: "VK-ссылка не отвечает: " + link,
				})
			}
		}
	}

	var st syscall.Statfs_t
	if err := syscall.Statfs(s.cfg.InstallDir, &st); err == nil {
		freeMB := int64(st.Bavail) * int64(st.Bsize) / (1024 * 1024)
		if freeMB < notifyDiskMinMB {
			alerts = append(alerts, notifyPayload{
				Type:    "disk_low",
				Message: "Свободное место на сервере: меньше 500 МБ",
			})
		}
	}

	capacity := s.cfg.MaxActive
	if capacity <= 0 {
		capacity = s.cfg.PortEnd - s.cfg.PortStart + 1
	}
	if capacity > 0 {
		var active int
		_ = s.db.QueryRow(`SELECT COUNT(*) FROM keys WHERE port IS NOT NULL AND activated_at IS NOT NULL`).Scan(&active)
		if active*100 >= capacity*notifyPortsPct {
			alerts = append(alerts, notifyPayload{
				Type:    "ports_low",
				Message: "Порты на исходе: активных ключей почти максимум",
			})
		}
	}

	return alerts
}

func (s *Server) postNotify(client *http.Client, a notifyPayload) bool {
	a.TS = time.Now().Unix()
	a.Version = APIVersion
	body, _ := json.Marshal(a)
	resp, err := client.Post(s.cfg.NotifyURL, "application/json", bytes.NewReader(body))
	if err != nil {
		log.Printf("[notify] %s: %v", a.Type, err)
		return false
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		log.Printf("[notify] %s: HTTP %d", a.Type, resp.StatusCode)
		return false
	}
	log.Printf("[notify] отправлено: %s", a.Type)
	return true
}

// sendPortDownWebhook отправляет событие port_down / port_recovered немедленно (1.4).
// Вызывается reconcile-циклом при ПЕРЕХОДЕ порта в down и обратно — не по расписанию,
// поэтому отдельный троттлинг не нужен. Молчит, если NotifyURL не задан.
// Назначается полю Server.notifyPortDown в NewServer (в тестах подменяется).
func (s *Server) sendPortDownWebhook(port int, recovered bool, reason string) {
	if s.cfg.NotifyURL == "" {
		return
	}
	a := notifyPayload{Port: port, Message: reason}
	if recovered {
		a.Type = "port_recovered"
	} else {
		a.Type = "port_down"
	}
	go func() {
		client := &http.Client{Timeout: 10 * time.Second}
		s.postNotify(client, a)
	}()
}
