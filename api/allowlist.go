package main

// Опциональный allowlist для /admin/* (D2). По умолчанию выключен: админка и бот
// ходят по X-Admin-Token с любого IP. Если задан -admin-allow / ADMIN_ALLOW,
// /admin/* отвечает 403 всем адресам вне списка (ещё до проверки токена).

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

// parseAllowList разбирает "1.2.3.4, 10.0.0.0/8, 2001:db8::/32" в список сетей.
// Одиночный IP превращается в /32 (или /128). Пустая строка → nil (allowlist выключен).
func parseAllowList(s string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, part := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == ';' }) {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if !strings.Contains(part, "/") {
			ip := net.ParseIP(part)
			if ip == nil {
				return nil, fmt.Errorf("неверный IP %q", part)
			}
			if ip4 := ip.To4(); ip4 != nil {
				part += "/32"
			} else {
				part += "/128"
			}
		}
		_, n, err := net.ParseCIDR(part)
		if err != nil {
			return nil, fmt.Errorf("неверная сеть %q: %v", part, err)
		}
		out = append(out, n)
	}
	return out, nil
}

// ipAllowed: пустой список — разрешено всем.
func ipAllowed(nets []*net.IPNet, ipStr string) bool {
	if len(nets) == 0 {
		return true
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// adminAllowed проверяет адрес клиента по allowlist. Берётся только RemoteAddr:
// X-Forwarded-For не учитывается (перед API нет доверенного прокси, заголовок подделывается).
func (s *Server) adminAllowed(r *http.Request) bool {
	return ipAllowed(s.cfg.AdminAllowNets, clientIP(r))
}
