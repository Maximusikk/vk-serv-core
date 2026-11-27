package main

// POST /vkauth — реле authorization VK для сетей, где HTTPS в VK задушен DPI
// (отчёты #4/#5: api.vk.me / login.vk.ru висят на таймауте → TURN не поднять).
//
// Клиент (ядро libvkturn) после провала локальной авторизации с kind=network
// просит сервер прогнать цепочку VKCalls от своего имени и вернуть TURN-креды.
// С сервера цепочка стабильно проходит (проверено: steps 1–5, без капчи).
//
// Защита:
//   - Bearer user_token (тот же, что у /report);
//   - IP-лимит до проверки токена (statusLimiter) + vkauthLimiter: до vkauthRateMax
//     запросов на КЛЮЧ за vkauthRateWin;
//   - глобальная одновременность vkauthConcurrency (цепочка = 5 внешних запросов);
//   - ссылка VK берётся из keys.vk_link (закреплена за ключом), фолбэк — VK_LINK
//     из config.txt; ссылка из тела запроса НЕ принимается (релей не должен
//     становиться прокси авторизации в чужие звонки).
//
// Ответ: {"user": "...", "pass": "...", "urls": ["ip:port", ...]} — те же поля,
// что возвращает локальная цепочка ядра.

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	vkauthRateMax       = 12              // запросов на ключ за окно (сессия = ≤3 группы × попытки)
	vkauthRateWin       = 10 * time.Minute
	vkauthBodyMax       = 1 << 10
	vkauthConcurrency   = 4               // одновременных цепочек (внешние запросы к VK)
	vkauthConnectBudget = 75 * time.Second // общий бюджет цепочки
)

// vkauthSem — семафор одновременных цепочек (в init не нужен: буферный канал).
var vkauthSem = make(chan struct{}, vkauthConcurrency)

// extractJoinHash достаёт хеш звонка из https://vk.ru|vk.com/call/join/<hash>[?...].
func extractJoinHash(link string) string {
	i := strings.Index(link, "call/join/")
	if i < 0 {
		return ""
	}
	h := link[i+len("call/join/"):]
	if j := strings.IndexAny(h, "?/&# \t\r\n"); j >= 0 {
		h = h[:j]
	}
	return h
}

// vkauthChainStep выполняет POST и декодирует JSON-ответ VK.
func vkauthChainStep(ctx context.Context, hc *http.Client, u string) (map[string]interface{}, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(""))
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en-GB,en;q=0.9")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("network: %w", err)
	}
	defer func() { _, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20)); _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	var out map[string]interface{}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	return out, nil
}

// vkauthAPIErr достает VK/OK ошибку из ответа; капча (error_code=14) — отдельная метка.
func vkauthAPIErr(resp map[string]interface{}) error {
	if errObj, ok := resp["error"].(map[string]interface{}); ok {
		code, _ := errObj["error_code"].(float64)
		msg, _ := errObj["error_msg"].(string)
		if code != 0 || msg != "" {
			if int(code) == 14 {
				return fmt.Errorf("vk_captcha")
			}
			return fmt.Errorf("vk_api error_code=%d %s", int(code), msg)
		}
	}
	if code, ok := resp["error_code"].(float64); ok && code != 0 {
		msg, _ := resp["error_msg"].(string)
		return fmt.Errorf("ok_api error_code=%d %s", int(code), msg)
	}
	return nil
}

func vkauthStr(resp map[string]interface{}, keys ...string) (string, error) {
	var cur interface{} = resp
	for _, k := range keys {
		m, ok := cur.(map[string]interface{})
		if !ok {
			return "", fmt.Errorf("bad shape at %q", k)
		}
		cur = m[k]
	}
	s, ok := cur.(string)
	if !ok {
		return "", fmt.Errorf("bad shape: not a string")
	}
	return s, nil
}

// vkauthChain — steps 1–5 цепочки VKCalls (совпадает с client/creds_vkcalls.go).
// Возвращает TURN-креды: username, credential, адреса (host:port).
func vkauthChain(ctx context.Context, hash string) (string, string, []string, error) {
	hc := &http.Client{Timeout: 20 * time.Second}
	eURL := url.QueryEscape("https://vk.com/call/join/" + hash)
	devID := newFakeUUID()
	name := url.QueryEscape("Alex Morgan")

	r1, err := vkauthChainStep(ctx, hc, "https://api.vk.me/method/auth.getAnonymToken?v=5.276&client_id=8093730&link="+eURL+
		"&device_id="+devID+"&anonymName="+name+"&lang=en")
	if err != nil {
		return "", "", nil, fmt.Errorf("step1: %w", err)
	}
	if e := vkauthAPIErr(r1); e != nil {
		return "", "", nil, fmt.Errorf("step1: %w", e)
	}
	t1, err := vkauthStr(r1, "response", "token")
	if err != nil {
		return "", "", nil, fmt.Errorf("step1: %w", err)
	}
	t1E := url.QueryEscape(t1)

	r2, err := vkauthChainStep(ctx, hc, "https://api.vk.me/method/messages.getCallPreview?v=5.276&anonymous_token="+t1E+
		"&device_id="+devID+"&extended=1&fields=first_name,last_name,photo_200&lang=en&link="+eURL)
	if err != nil {
		return "", "", nil, fmt.Errorf("step2: %w", err)
	}
	if e := vkauthAPIErr(r2); e != nil {
		return "", "", nil, fmt.Errorf("step2: %w", e)
	}
	userIDF, ok := r2["response"].(map[string]interface{})["user_id"].(float64)
	if !ok {
		return "", "", nil, fmt.Errorf("step2: user_id missing")
	}
	secret, err := vkauthStr(r2, "response", "secret")
	if err != nil {
		return "", "", nil, fmt.Errorf("step2: %w", err)
	}

	r3, err := vkauthChainStep(ctx, hc, "https://api.vk.me/method/messages.getAnonymCallToken?v=5.276&anonymous_token="+t1E+
		"&device_id="+devID+"&link="+eURL+"&name="+name+"&user_id="+strconv.FormatInt(int64(userIDF), 10)+
		"&secret="+url.QueryEscape(secret)+"&lang=en")
	if err != nil {
		return "", "", nil, fmt.Errorf("step3: %w", err)
	}
	if e := vkauthAPIErr(r3); e != nil {
		return "", "", nil, fmt.Errorf("step3: %w", e)
	}
	okToken, err := vkauthStr(r3, "response", "token")
	if err != nil {
		return "", "", nil, fmt.Errorf("step3: %w", err)
	}

	sessionData := fmt.Sprintf(`{"version":2,"device_id":"%s","client_version":"1.0.1"}`, newFakeUUID())
	r4, err := vkauthChainStep(ctx, hc, "https://calls.okcdn.ru/fb.do?session_data="+url.QueryEscape(sessionData)+
		"&method=auth.anonymLogin&format=JSON&application_key=CGMMEJLGDIHBABABA")
	if err != nil {
		return "", "", nil, fmt.Errorf("step4: %w", err)
	}
	if e := vkauthAPIErr(r4); e != nil {
		return "", "", nil, fmt.Errorf("step4: %w", e)
	}
	sessionKey, err := vkauthStr(r4, "session_key")
	if err != nil {
		return "", "", nil, fmt.Errorf("step4: %w", err)
	}

	r5, err := vkauthChainStep(ctx, hc, "https://calls.okcdn.ru/fb.do?joinLink="+url.QueryEscape(hash)+
		"&isVideo=false&protocolVersion=5&anonymToken="+url.QueryEscape(okToken)+
		"&method=vchat.joinConversationByLink&format=JSON&application_key=CGMMEJLGDIHBABABA&session_key="+url.QueryEscape(sessionKey))
	if err != nil {
		return "", "", nil, fmt.Errorf("step5: %w", err)
	}
	if e := vkauthAPIErr(r5); e != nil {
		return "", "", nil, fmt.Errorf("step5: %w", e)
	}
	ts, ok := r5["turn_server"].(map[string]interface{})
	if !ok {
		return "", "", nil, fmt.Errorf("step5: turn_server missing")
	}
	user, err := vkauthStr(ts, "username")
	if err != nil {
		return "", "", nil, fmt.Errorf("step5: %w", err)
	}
	pass, err := vkauthStr(ts, "credential")
	if err != nil {
		return "", "", nil, fmt.Errorf("step5: %w", err)
	}
	urlsRaw, ok := ts["urls"].([]interface{})
	if !ok || len(urlsRaw) == 0 {
		return "", "", nil, fmt.Errorf("step5: turn_server.urls empty")
	}
	var addrs []string
	for _, u := range urlsRaw {
		s, ok := u.(string)
		if !ok {
			continue
		}
		s = strings.SplitN(s, "?", 2)[0]
		s = strings.TrimPrefix(strings.TrimPrefix(s, "turns:"), "turn:")
		if s != "" {
			addrs = append(addrs, s)
		}
	}
	if len(addrs) == 0 {
		return "", "", nil, fmt.Errorf("step5: no usable turn urls")
	}
	return user, pass, addrs, nil
}

// newFakeUUID — uuid-v4 из crypto/rand (VK не проверяет вариант/вариант-биты,
// но держим формат, как у клиента: 8-4-4-4-12 hex).
func newFakeUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		t := time.Now().UnixNano()
		for i := range b {
			b[i] = byte(t >> (8 * uint(i)))
		}
	}
	const hexd = "0123456789abcdef"
	out := make([]byte, 36)
	k := 0
	for i := 0; i < 16; i++ {
		if i == 4 || i == 6 || i == 8 || i == 10 {
			out[k] = '-'
			k++
		}
		out[k] = hexd[b[i]>>4]
		out[k+1] = hexd[b[i]&0x0f]
		k += 2
	}
	return string(out)
}

func logVKAuthErr(keyID string, err error) {
	log.Printf("[vkauth] key=%s chain failed: %v", keyID, err)
}

// handleVKAuth — POST /vkauth. Bearer user_token → TURN-креды через серверную цепочку.
func (s *Server) handleVKAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	token := bearerToken(r)
	if token == "" {
		jsonError(w, "authorization required", http.StatusUnauthorized)
		return
	}
	if r.ContentLength > vkauthBodyMax {
		jsonError(w, "bad request", http.StatusRequestEntityTooLarge)
		return
	}

	var keyID string
	var keyLink sql.NullString
	if err := s.db.QueryRow(
		`SELECT id, vk_link FROM keys WHERE user_token = ? AND activated_at IS NOT NULL`, token,
	).Scan(&keyID, &keyLink); err != nil {
		jsonError(w, "token not found", http.StatusNotFound)
		return
	}

	if s.vkauthLimiter.blocked(keyID) {
		w.Header().Set("Retry-After", strconv.Itoa(int(vkauthRateWin/time.Second)))
		jsonErrorCode(w, "vkauth rate limit", "rate_limited", http.StatusTooManyRequests)
		return
	}

	link := strings.TrimSpace(keyLink.String)
	if link == "" {
		if _, _, cfgLink, err := s.readMainConfig(); err == nil {
			link = cfgLink
		}
	}
	hash := extractJoinHash(link)
	if hash == "" {
		jsonError(w, "vk link not configured for this key", http.StatusServiceUnavailable)
		return
	}

	// Бюджет + одновременность: цепочка — 5 внешних запросов, держим слот.
	select {
	case vkauthSem <- struct{}{}:
		defer func() { <-vkauthSem }()
	default:
		jsonErrorCode(w, "server busy, retry later", "busy", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), vkauthConnectBudget)
	defer cancel()

	user, pass, addrs, err := vkauthChain(ctx, hash)
	if err != nil {
		logVKAuthErr(keyID, err)
		jsonErrorCode(w, "vk auth failed on server", "vk_auth_failed", http.StatusBadGateway)
		return
	}
	jsonOK(w, map[string]any{"user": user, "pass": pass, "urls": addrs})
}
