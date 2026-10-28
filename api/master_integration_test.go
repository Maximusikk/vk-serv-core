package main

// Интеграционный тест этапа 3 (мастер): НАСТОЯЩИЙ TLS до фейковых нод.
// В отличие от master_cycles_test.go (фейковый RoundTripper), здесь мастер ходит
// к нодам через реальный pinnedTransport → dialPinned: SPKI-пин проверяется на
// рукопожатии. Тики (resend/traffic/health) вызываются напрямую — без ожидания
// реальных интервалов 30/60 с.

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// ── фейковая нода: настоящий TLS-сервер ──────────────────────────────────────────

type fakeUsage struct {
	ID    int64  `json:"id"`
	KeyID string `json:"key_id"`
	ExtID string `json:"external_id"`
	Bytes int64  `json:"bytes"`
}

type fakeNode struct {
	mu    sync.Mutex
	t     *testing.T
	name  string
	addr  string
	pin   string
	cert  tls.Certificate
	srv   *http.Server
	ls    net.Listener
	keyN  int
	keys  map[string]string   // external_id -> key_id
	crBodies []map[string]any // тела keys/create
	revoked  map[string]bool
	usage []fakeUsage
	up    bool
}

func startFakeNode(t *testing.T, name string) *fakeNode {
	t.Helper()
	cert, err := ensureCert(t.TempDir(), nil)
	if err != nil {
		t.Fatalf("ensureCert: %v", err)
	}
	n := &fakeNode{
		t: t, name: name,
		pin:  spkiPin(cert.Leaf),
		cert: cert,
		keys: map[string]string{}, revoked: map[string]bool{},
	}
	n.srv = &http.Server{Handler: n.mux()}
	ls, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	n.ls = ls
	n.addr = ls.Addr().String()
	n.up = true
	go n.srv.Serve(tls.NewListener(ls, serverTLSConfig(cert)))
	t.Cleanup(func() { n.srv.Close() })
	return n
}

// down закрывает listener (мастер получает connection refused).
func (n *fakeNode) down() {
	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.up {
		return
	}
	n.up = false
	n.ls.Close()
}

// up поднимает listener на том же адресе.
func (n *fakeNode) up2() {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.up {
		return
	}
	ls, err := net.Listen("tcp", n.addr)
	if err != nil {
		n.t.Fatalf("re-listen %s: %v", n.addr, err)
	}
	n.ls = ls
	n.up = true
	go n.srv.Serve(tls.NewListener(ls, serverTLSConfig(n.cert)))
}

func (n *fakeNode) addUsage(keyID, extID string, bytes int64) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.usage = append(n.usage, fakeUsage{ID: int64(len(n.usage) + 1), KeyID: keyID, ExtID: extID, Bytes: bytes})
}

func (n *fakeNode) keyFor(extID string) string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.keys[extID]
}

func (n *fakeNode) isRevoked(keyID string) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.revoked[keyID]
}

func (n *fakeNode) createBody(extID string) map[string]any {
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, b := range n.crBodies {
		if b["external_id"] == extID {
			return b
		}
	}
	return nil
}

func (n *fakeNode) mux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/admin/keys/create", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		raw, _ := io.ReadAll(r.Body)
		json.Unmarshal(raw, &body)
		ext, _ := body["external_id"].(string)
		n.mu.Lock()
		n.keyN++
		key := fmt.Sprintf("key-%s-%d", n.name, n.keyN)
		n.keys[ext] = key
		n.crBodies = append(n.crBodies, body)
		n.mu.Unlock()
		jsonOK(w, map[string]any{"key": key})
	})
	mux.HandleFunc("/v1/admin/health", func(w http.ResponseWriter, r *http.Request) {
		jsonOK(w, map[string]any{"status": "ok"})
	})
	mux.HandleFunc("/v1/admin/usage", func(w http.ResponseWriter, r *http.Request) {
		var since int64
		fmt.Sscanf(r.URL.Query().Get("since"), "%d", &since)
		n.mu.Lock()
		items := []fakeUsage{}
		next := since
		for _, u := range n.usage {
			if u.ID > since {
				items = append(items, u)
				next = u.ID
			}
		}
		n.mu.Unlock()
		jsonOK(w, map[string]any{"items": items, "next": next})
	})
	mux.HandleFunc("/v1/admin/keys/", func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimSuffix(r.URL.Path, "/")
		switch {
		case strings.HasSuffix(p, "/revoke"):
			key := strings.TrimSuffix(strings.TrimPrefix(p, "/v1/admin/keys/"), "/revoke")
			n.mu.Lock()
			n.revoked[key] = true
			n.mu.Unlock()
			jsonOK(w, map[string]any{"ok": true})
		case r.Method == http.MethodGet:
			// Ключ трактуется как активированный: expires_at = now + 30 дней
			// (нужно restoreExpiresDays при досыле).
			jsonOK(w, map[string]any{"expires_at": time.Now().Add(30 * 24 * time.Hour).Unix()})
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	})
	return mux
}

// ── хелперы мастера ──────────────────────────────────────────────────────────────

func masterCall(t *testing.T, mux *http.ServeMux, method, path, body string, wantCode int) map[string]any {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = "198.51.100.77:1111"
	req.Header.Set("X-Admin-Token", "adm")
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != wantCode {
		t.Fatalf("%s %s: want %d, got %d: %s", method, path, wantCode, w.Code, w.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("%s %s: json: %v (%s)", method, path, err, w.Body.String())
	}
	return out
}

func subIDByExt(t *testing.T, s *Server, ext string) int64 {
	t.Helper()
	var id int64
	if err := s.db.QueryRow(`SELECT id FROM subscriptions WHERE external_id = ?`, ext).Scan(&id); err != nil {
		t.Fatalf("подписка %s: %v", ext, err)
	}
	return id
}

func ssStatus(t *testing.T, s *Server, subID, serverID int64) (status, keyID, errText string) {
	t.Helper()
	if err := s.db.QueryRow(`SELECT status, key_id, error FROM subscription_servers WHERE sub_id=? AND server_id=?`,
		subID, serverID).Scan(&status, &keyID, &errText); err != nil {
		t.Fatalf("subscription_servers: %v", err)
	}
	return
}

// ── сам тест ─────────────────────────────────────────────────────────────────────

func TestMasterEndToEnd(t *testing.T) {
	// Приёмник вебхуков (healthTick шлёт node_down/node_up).
	hooks := &hookLog{}
	hookSrv := newTestHookServer(t, hooks)

	// Мастер: реальный pinned-транспорт, реальные маршруты.
	s, _ := newTestServer(t)
	// MaxOpenConns(1), как в проде: GET /master/subscriptions не должен виснуть (регрессия дедлока).
	s.cfg.Mode = masterMode
	s.cfg.AdminToken = "adm"
	s.cfg.NotifyURL = hookSrv.URL
	mux := http.NewServeMux()
	registerRoutes(mux, s)

	// Две ноды с настоящим TLS.
	node1 := startFakeNode(t, "n1")
	node2 := startFakeNode(t, "n2")

	// ── Join через одноразовые токены ────────────────────────────────────────────
	join := func(n *fakeNode, mtok string) {
		t.Helper()
		out := masterCall(t, mux, "POST", "/v1/master/join-tokens", "", 200)
		tok, _ := out["token"].(string)
		if tok == "" {
			t.Fatal("join-tokens: пустой токен")
		}
		body := fmt.Sprintf(`{"token":%q,"api":%q,"pin":%q,"master_token":%q,"name":%q}`,
			tok, n.addr, n.pin, mtok, n.name)
		masterCall(t, mux, "POST", "/v1/master/join", body, 200)

		// Одноразовость: тот же токен второй раз → 403.
		masterCall(t, mux, "POST", "/v1/master/join", body, 403)
	}
	join(node1, "mt-1")
	join(node2, "mt-2")

	// Ноды видны в /master/servers.
	srvs := masterCall(t, mux, "GET", "/v1/master/servers", "", 200)
	list := srvs["servers"].([]any)
	if len(list) != 2 {
		t.Fatalf("хочу 2 ноды, got %d", len(list))
	}

	// ── 1. Раскатка подписки ─────────────────────────────────────────────────────
	out := masterCall(t, mux, "POST", "/v1/master/subscriptions",
		`{"external_id":"order-1","name":"S","bytes_limit":1000,"expires_days":30}`, 200)
	if got := int(out["delivered"].(float64)); got != 2 {
		t.Fatalf("delivered = %d, хочу 2 (%s)", got, out)
	}
	serversOut := out["servers"].([]any)
	if len(serversOut) != 2 {
		t.Fatalf("servers: %d", len(serversOut))
	}
	for _, sv := range serversOut {
		if st := sv.(map[string]any)["status"]; st != subActive {
			t.Fatalf("статус доставки %v, хочу active", st)
		}
	}
	sub1 := int64(out["id"].(float64))

	// bundle: vkturn://bundle/… → {v:1,n:"S",s:[2 сервера],limit:1000}
	bundle, _ := out["bundle"].(string)
	if !strings.HasPrefix(bundle, "vkturn://bundle/") {
		t.Fatalf("bundle %q", bundle)
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(bundle, "vkturn://bundle/"))
	if err != nil {
		t.Fatalf("bundle decode: %v", err)
	}
	var bp struct {
		V     int    `json:"v"`
		N     string `json:"n"`
		S     []struct {
			API  string `json:"api"`
			Pin  string `json:"pin"`
			Key  string `json:"key"`
			Name string `json:"name"`
		} `json:"s"`
		Limit *int64 `json:"limit"`
	}
	if err := json.Unmarshal(raw, &bp); err != nil {
		t.Fatalf("bundle json: %v", err)
	}
	if bp.V != 1 || bp.N != "S" || len(bp.S) != 2 || bp.Limit == nil || *bp.Limit != 1000 {
		t.Fatalf("bundle payload: %+v", bp)
	}
	for _, ss := range bp.S {
		if ss.API != node1.addr && ss.API != node2.addr {
			t.Fatalf("bundle: неожиданный api %q", ss.API)
		}
		if ss.Pin != node1.pin && ss.Pin != node2.pin {
			t.Fatalf("bundle: пин не совпадает с пином нод: %q", ss.Pin)
		}
		if ss.Key == "" {
			t.Fatal("bundle: пустой key")
		}
	}

	// Ноды получили create с local_limit=1000 и external_id="order-1".
	for _, n := range []*fakeNode{node1, node2} {
		b := n.createBody("order-1")
		if b == nil {
			t.Fatalf("%s: create не дошёл", n.name)
		}
		if ll, _ := b["local_limit"].(float64); ll != 1000 {
			t.Fatalf("%s: local_limit = %v, хочу 1000", n.name, b["local_limit"])
		}
		if bl, _ := b["bytes_limit"].(float64); bl != 1000 {
			t.Fatalf("%s: bytes_limit = %v", n.name, b["bytes_limit"])
		}
	}

	// ── 2. Pending → досыл (resendTick напрямую) ────────────────────────────────
	if _, err := s.db.Exec(`UPDATE servers SET status='down' WHERE api=?`, node2.addr); err != nil {
		t.Fatal(err)
	}
	out2 := masterCall(t, mux, "POST", "/v1/master/subscriptions",
		`{"external_id":"order-2","name":"S2","bytes_limit":500,"expires_days":30}`, 200)
	if got := int(out2["delivered"].(float64)); got != 1 {
		t.Fatalf("order-2: delivered = %d, хочу 1", got)
	}
	sub2 := int64(out2["id"].(float64))
	node2ID := int64(0)
	for _, sv := range out2["servers"].([]any) {
		m := sv.(map[string]any)
		if m["api"] == node2.addr {
			if m["status"] != subPending {
				t.Fatalf("order-2 node2: status=%v, хочу pending", m["status"])
			}
			node2ID = int64(m["server_id"].(float64))
		}
	}
	if node2ID == 0 {
		t.Fatal("order-2: нода 2 не найдена в ответе")
	}

	if _, err := s.db.Exec(`UPDATE servers SET status='active' WHERE api=?`, node2.addr); err != nil {
		t.Fatal(err)
	}
	s.resendTick() // досыл напрямую, без ожидания 30 с
	st, key2, errText := ssStatus(t, s, sub2, node2ID)
	if st != subActive || key2 == "" {
		t.Fatalf("order-2 после досыла: status=%q key=%q err=%q", st, key2, errText)
	}
	if node2.keyFor("order-2") != key2 {
		t.Fatalf("order-2: нода 2 не получила create (key=%q)", key2)
	}

	// ── 3. Сумма трафика (trafficTick напрямую) ─────────────────────────────────
	key1 := node1.keyFor("order-1")
	key2o1 := node2.keyFor("order-1")
	if key1 == "" || key2o1 == "" {
		t.Fatal("нет ключей order-1 на нодах")
	}
	node1.addUsage(key1, "order-1", 400)
	node2.addUsage(key2o1, "order-1", 300)
	s.trafficTick()

	subs := masterCall(t, mux, "GET", "/v1/master/subscriptions", "", 200)["subscriptions"].([]any)
	usedOf := func(ext string) (float64, bool) {
		for _, v := range subs {
			m := v.(map[string]any)
			if m["external_id"] == ext {
				return m["bytes_used"].(float64), true
			}
		}
		return 0, false
	}
	if u, ok := usedOf("order-1"); !ok || u != 700 {
		t.Fatalf("bytes_used = %v, хочу 700", subs)
	}

	// Повторный тик без новых дельт — не задвоилось.
	s.trafficTick()
	subs = masterCall(t, mux, "GET", "/v1/master/subscriptions", "", 200)["subscriptions"].([]any)
	if u, _ := usedOf("order-1"); u != 700 {
		t.Fatalf("после повторного тика bytes_used = %v, хочу 700", u)
	}

	// Новые дельты — сумма растёт.
	node1.addUsage(key1, "order-1", 50)
	s.trafficTick()
	subs = masterCall(t, mux, "GET", "/v1/master/subscriptions", "", 200)["subscriptions"].([]any)
	if u, _ := usedOf("order-1"); u != 750 {
		t.Fatalf("после +50 bytes_used = %v, хочу 750", u)
	}

	// Нода 2 недоступна (listener закрыт): дельты не теряются, since не двигается.
	node2.addUsage(key2o1, "order-1", 100)
	node2.down()
	node2Since := func() float64 {
		t.Helper()
		sv := masterCall(t, mux, "GET", "/v1/master/servers", "", 200)["servers"].([]any)
		for _, v := range sv {
			m := v.(map[string]any)
			if m["api"] == node2.addr {
				return m["since"].(float64)
			}
		}
		t.Fatal("нода 2 не найдена в /master/servers")
		return 0
	}
	sinceBefore := node2Since()
	node1.addUsage(key1, "order-1", 50)
	s.trafficTick()
	subs = masterCall(t, mux, "GET", "/v1/master/subscriptions", "", 200)["subscriptions"].([]any)
	if u, _ := usedOf("order-1"); u != 800 {
		t.Fatalf("при недоступной ноде bytes_used = %v, хочу 800 (+50 только с ноды 1)", u)
	}
	if since := node2Since(); since != sinceBefore {
		t.Fatalf("since ноды 2 сдвинулся при сбое: %v → %v", sinceBefore, since)
	}

	// Нода вернулась — недочитанные дельты добираются.
	node2.up2()
	s.trafficTick()
	subs = masterCall(t, mux, "GET", "/v1/master/subscriptions", "", 200)["subscriptions"].([]any)
	if u, _ := usedOf("order-1"); u != 900 {
		t.Fatalf("после восстановления bytes_used = %v, хочу 900 (+100 добраны)", u)
	}

	// ── 4. Отзыв везде при превышении лимита ────────────────────────────────────
	node1.addUsage(key1, "order-1", 200)
	node2.addUsage(key2o1, "order-1", 100)
	s.trafficTick() // 900 + 300 = 1200 >= 1000 → revoke
	subs = masterCall(t, mux, "GET", "/v1/master/subscriptions", "", 200)["subscriptions"].([]any)
	if u, _ := usedOf("order-1"); u != 1200 {
		t.Fatalf("bytes_used = %v, хочу 1200", u)
	}
	if !node1.isRevoked(key1) || !node2.isRevoked(key2o1) {
		t.Fatalf("revoke не дошёл до нод: n1(%s)=%v n2(%s)=%v", key1, node1.isRevoked(key1), key2o1, node2.isRevoked(key2o1))
	}
	var revokedAt any
	if err := s.db.QueryRow(`SELECT revoked_at FROM subscriptions WHERE id=?`, sub1).Scan(&revokedAt); err != nil || revokedAt == nil {
		t.Fatalf("revoked_at не выставлен (err=%v val=%v)", err, revokedAt)
	}

	// ── 6. Неверный пин ноды: dispatch failed «tls pin mismatch», healthTick → down ──
	node3 := startFakeNode(t, "n3")
	// join с чужим (но валидным) пином — пин node1 вместо пина node3.
	out3 := masterCall(t, mux, "POST", "/v1/master/join-tokens", "", 200)
	tok3, _ := out3["token"].(string)
	masterCall(t, mux, "POST", "/v1/master/join", fmt.Sprintf(
		`{"token":%q,"api":%q,"pin":%q,"master_token":"mt-3","name":"n3"}`,
		tok3, node3.addr, node1.pin), 200) // join принимает любой hex64
	node3ID := int64(masterCall(t, mux, "GET", "/v1/master/servers", "", 200)["servers"].([]any)[2].(map[string]any)["id"].(float64))

	// dispatch (нода ещё 'active'): dispatchSubscription реально звонит на ноду,
	// dialPinned отвергает сертификат → failed с «tls pin mismatch».
	out9 := masterCall(t, mux, "POST", "/v1/master/subscriptions",
		`{"external_id":"order-9","name":"S9","bytes_limit":0,"expires_days":30}`, 200)
	sub9 := int64(out9["id"].(float64))
	st, _, errText = ssStatus(t, s, sub9, node3ID)
	if st != subFailed || !strings.Contains(errText, "tls pin mismatch") {
		t.Fatalf("order-9 нода 3: status=%q err=%q, хочу failed/tls pin mismatch", st, errText)
	}
	// Ноды 1 и 2 (верные пины) получили ключ.
	if out9["delivered"].(float64) != 2 {
		t.Fatalf("order-9: delivered = %v, хочу 2", out9["delivered"])
	}

	// healthTick: реальный dialPinned отвергает сертификат → нода 3 down.
	s.healthTick()
	svList := masterCall(t, mux, "GET", "/v1/master/servers", "", 200)["servers"].([]any)
	for _, v := range svList {
		m := v.(map[string]any)
		if m["api"] == node3.addr && m["status"] != "down" {
			t.Fatalf("нода 3 с неверным пином: status=%v, хочу down", m["status"])
		}
	}
}
