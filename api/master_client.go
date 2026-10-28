package main

// Этап 3: HTTP-клиент мастера к нодам. Тот же путь, что у бота (vkturn_client.py):
// TLS с проверкой SPKI-пина листового сертификата ДО отправки master-token.
// CA и имя хоста не проверяются — допустимо только потому, что пин обязателен.

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

type pinKey struct{}

// dialPinned — TLS-соединение с проверкой пина (hostname/CA не проверяются,
// их заменяет пин). Пустой пин запрещён.
func dialPinned(ctx context.Context, network, addr, pin string) (net.Conn, error) {
	if pin == "" {
		return nil, fmt.Errorf("dialPinned: пустой пин запрещён")
	}
	d := &net.Dialer{Timeout: 10 * time.Second}
	raw, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12} // пин ниже
	c := tls.Client(raw, cfg)
	if err := c.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	peer := c.ConnectionState().PeerCertificates
	if len(peer) == 0 {
		c.Close()
		return nil, fmt.Errorf("нода не прислала сертификат")
	}
	if actual := spkiPin(peer[0]); actual != pin {
		c.Close()
		return nil, fmt.Errorf("tls pin mismatch: ожидался %s, получен %s", pin, actual)
	}
	return c, nil
}

// pinnedTransport строит TLS-соединение с пином из контекста запроса.
type pinnedTransport struct{}

func (pinnedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	pin, _ := req.Context().Value(pinKey{}).(string)
	// Транспорт на каждый запрос (пин свой у каждой ноды): без keep-alive, иначе
	// простаивающие соединения брошенных транспортов никогда не закрываются
	// и мастер за сутки циклов опроса упирается в лимит дескрипторов.
	tr := &http.Transport{
		DisableKeepAlives: true,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialPinned(ctx, network, addr, pin)
		},
	}
	return tr.RoundTrip(req)
}

// nodeCall выполняет запрос к ноде: https://<api><path> c X-Admin-Token = master-token ноды.
// Пин проверяется при рукопожатии, ДО отправки заголовков. out — необязательный JSON-приёмник.
func (s *Server) nodeCall(node nodeRow, method, path string, body, out any) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, "https://"+node.API+path, rdr)
	if err != nil {
		return err
	}
	req = req.WithContext(context.WithValue(req.Context(), pinKey{}, node.Pin))
	req.Header.Set("X-Admin-Token", node.MasterToken)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := s.masterHTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 400 {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(raw, &e)
		if e.Error != "" {
			return fmt.Errorf("HTTP %d: %s", resp.StatusCode, e.Error)
		}
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if out != nil && len(raw) > 0 {
		return json.Unmarshal(raw, out)
	}
	return nil
}
