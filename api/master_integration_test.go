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
	patches  map[string][]map[string]any // key_id -> тела PATCH (extend/traffic)
	revoked  map[string]bool
	unbound  map[string]bool
	unbind429 map[string]bool // key_id -> отвечать 429 (7-дневный лимит)
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
		patches:   map[string][]map[string]any{},
		unbound:   map[string]bool{},
		unbind429: map[string]bool{},
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

func (n *fakeNode) patchBodies(keyID string) []map[string]any {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.patches[keyID]
}

func (n *fakeNode) isUnbound(keyID string) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.unbound[keyID]
}

func (n *fakeNode) setUnbind429(keyID string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.unbind429[keyID] = true
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
		case strings.HasSuffix(p, "/unbind"):
			key := strings.TrimSuffix(strings.TrimPrefix(p, "/v1/admin/keys/"), "/unbind")
			n.mu.Lock()
			defer n.mu.Unlock()
			if n.unbind429[key] {
				jsonError(w, "unbind allowed once per 7 days; try again in 96 h", http.StatusTooManyRequests)
				return
			}
			n.unbound[key] = true
			jsonOK(w, map[string]any{"status": "unbound"})
		case r.Method == http.MethodPatch:
			key := strings.TrimPrefix(p, "/v1/admin/keys/")
			var body map[string]any
			raw, _ := io.ReadAll(r.Body)
			json.Unmarshal(raw, &body)
			n.mu.Lock()
			n.patches[key] = append(n.patches[key], body)
			n.mu.Unlock()
			jsonOK(w, map[string]any{"status": "updated"})
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
	return masterCallWithToken(t, mux, method, path, body, wantCode, "X-Admin-Token", "adm")
}

// masterCallWithToken — masterCall с произвольным авторизационным заголовком
// (X-Master-Token для операций реестра нод).
func masterCallWithToken(t *testing.T, mux *http.ServeMux, method, path, body string, wantCode int, header, token string) map[string]any {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = "198.51.100.77:1111"
	req.Header.Set(header, token)
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
	s.cfg.MasterToken = "mtk" // операции реестра нод (join-tokens, DELETE servers)
	s.cfg.NotifyURL = hookSrv.URL
	mux := http.NewServeMux()
	registerRoutes(mux, s)

	// Две ноды с настоящим TLS.
	node1 := startFakeNode(t, "n1")
	node2 := startFakeNode(t, "n2")

	// ── Join через одноразовые токены ────────────────────────────────────────────
	join := func(n *fakeNode, mtok string) {
		t.Helper()
		out := masterCallWithToken(t, mux, "POST", "/v1/master/join-tokens", "", 200, "X-Master-Token", "mtk")
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
		// Имя ноды (из join) — чтобы клиент отличал серверы в группе.
		wantName := "n1"
		if ss.API == node2.addr {
			wantName = "n2"
		}
		if ss.Name != wantName {
			t.Fatalf("bundle: name = %q, хочу %q", ss.Name, wantName)
		}
	}

	// nodeDisplayName: фолбек на хост при пустом имени.
	for in, want := range map[string]string{
		"1.2.3.4:7000":              "1.2.3.4",
		"https://node.example:7000": "node.example",
		"node.example":              "node.example",
		"[2001:db8::1]:7000":        "2001:db8::1",
	} {
		if got := nodeDisplayName("  ", in); got != want {
			t.Fatalf("nodeDisplayName(%q) = %q, хочу %q", in, got, want)
		}
	}
	if got := nodeDisplayName(" DE-1 ", "1.2.3.4:7000"); got != "DE-1" {
		t.Fatalf("nodeDisplayName with name = %q", got)
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
	out3 := masterCallWithToken(t, mux, "POST", "/v1/master/join-tokens", "", 200, "X-Master-Token", "mtk")
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

// ── Жизненный цикл подписки: extend / add_traffic / revoke / unbind ─────────────

func TestSubscriptionLifecycle(t *testing.T) {
	s, _ := newTestServer(t)
	s.cfg.Mode = masterMode
	s.cfg.AdminToken = "adm"
	s.cfg.MasterToken = "mtk"
	mux := http.NewServeMux()
	registerRoutes(mux, s)

	node1 := startFakeNode(t, "n1")
	node2 := startFakeNode(t, "n2")
	join := func(n *fakeNode, mtok string) {
		t.Helper()
		out := masterCallWithToken(t, mux, "POST", "/v1/master/join-tokens", "", 200, "X-Master-Token", "mtk")
		tok, _ := out["token"].(string)
		body := fmt.Sprintf(`{"token":%q,"api":%q,"pin":%q,"master_token":%q,"name":%q}`,
			tok, n.addr, n.pin, mtok, n.name)
		masterCall(t, mux, "POST", "/v1/master/join", body, 200)
	}
	join(node1, "mt-1")
	join(node2, "mt-2")

	out := masterCall(t, mux, "POST", "/v1/master/subscriptions",
		`{"external_id":"lc-1","name":"LC","bytes_limit":1000,"expires_days":30}`, 200)
	subID := int64(out["id"].(float64))
	if got := int(out["delivered"].(float64)); got != 2 {
		t.Fatalf("delivered = %d, хочу 2", got)
	}

	// ── Продление: fan-out PATCH {expires_days} на обе ноды ─────────────────────
	// Подписки — под админ-токеном (токен продавца).
	out = masterCall(t, mux, "PATCH", fmt.Sprintf("/v1/master/subscriptions/%d", subID), `{"expires_days":15}`, 200)
	if st, _ := out["status"].(string); st != "updated" {
		t.Fatalf("patch status = %v (%s)", out["status"], out["results"])
	}
	for _, nd := range []*fakeNode{node1, node2} {
		bs := nd.patchBodies(nd.keyFor("lc-1"))
		if len(bs) != 1 {
			t.Fatalf("%s: патчей %d, хочу 1", nd.name, len(bs))
		}
		if d, _ := bs[0]["expires_days"].(float64); d != 15 {
			t.Fatalf("%s: expires_days = %v, хочу 15", nd.name, bs[0]["expires_days"])
		}
	}
	// Валидация: 0 и > 3650 → 400.
	masterCall(t, mux, "PATCH", fmt.Sprintf("/v1/master/subscriptions/%d", subID), `{"expires_days":0}`, 400)
	masterCall(t, mux, "PATCH", fmt.Sprintf("/v1/master/subscriptions/%d", subID), `{"expires_days":9999}`, 400)

	// ── Докупка трафика: sub.bytes_limit растёт, ноды получают новый общий лимит ──
	out = masterCall(t, mux, "POST", fmt.Sprintf("/v1/master/subscriptions/%d/add_traffic", subID), `{"bytes":500}`, 200)
	if st, _ := out["status"].(string); st != "updated" {
		t.Fatalf("add_traffic status = %v", out["status"])
	}
	var bl int64
	if err := s.db.QueryRow(`SELECT bytes_limit FROM subscriptions WHERE id=?`, subID).Scan(&bl); err != nil || bl != 1500 {
		t.Fatalf("sub bytes_limit = %d (err=%v), хочу 1500", bl, err)
	}
	for _, nd := range []*fakeNode{node1, node2} {
		bs := nd.patchBodies(nd.keyFor("lc-1"))
		if len(bs) != 2 {
			t.Fatalf("%s: патчей %d, хочу 2 (extend + traffic)", nd.name, len(bs))
		}
		last := bs[len(bs)-1]
		if v, _ := last["bytes_limit"].(float64); v != 1500 {
			t.Fatalf("%s: bytes_limit = %v, хочу 1500", nd.name, last["bytes_limit"])
		}
		if v, _ := last["local_limit"].(float64); v != 1500 {
			t.Fatalf("%s: local_limit = %v, хочу 1500", nd.name, last["local_limit"])
		}
	}

	// Безлимитная подписка → 400 (паритет с нодой).
	outU := masterCall(t, mux, "POST", "/v1/master/subscriptions",
		`{"external_id":"lc-unlim","name":"U","bytes_limit":0,"expires_days":30}`, 200)
	subU := int64(outU["id"].(float64))
	masterCall(t, mux, "POST", fmt.Sprintf("/v1/master/subscriptions/%d/add_traffic", subU), `{"bytes":100}`, 400)

	// ── Отзыв: revoked_at у подписки + revoke на обеих нодах, идемпотентно ───────
	out = masterCall(t, mux, "POST", fmt.Sprintf("/v1/master/subscriptions/%d/revoke", subID), "", 200)
	if st, _ := out["status"].(string); st != "revoked" {
		t.Fatalf("revoke status = %v", out["status"])
	}
	if !node1.isRevoked(node1.keyFor("lc-1")) || !node2.isRevoked(node2.keyFor("lc-1")) {
		t.Fatal("revoke не дошёл до нод")
	}
	var ra any
	if err := s.db.QueryRow(`SELECT revoked_at FROM subscriptions WHERE id=?`, subID).Scan(&ra); err != nil || ra == nil {
		t.Fatalf("revoked_at не выставлен (err=%v val=%v)", err, ra)
	}
	out = masterCall(t, mux, "POST", fmt.Sprintf("/v1/master/subscriptions/%d/revoke", subID), "", 200)
	if v, _ := out["already_revoked"].(bool); !v {
		t.Fatalf("повторный revoke: хочу already_revoked, got %v", out)
	}

	// ── Unbind: 200 на ноде 1, 429 на ноде 2 → частичный успех в results ────────
	node2.setUnbind429(node2.keyFor("lc-1"))
	out = masterCall(t, mux, "POST", fmt.Sprintf("/v1/master/subscriptions/%d/unbind", subID), "", 200)
	results, _ := out["results"].([]any)
	if len(results) != 2 {
		t.Fatalf("unbind results = %d, хочу 2", len(results))
	}
	okCount, failCount := 0, 0
	for _, v := range results {
		m := v.(map[string]any)
		switch m["status"] {
		case "ok":
			okCount++
		case "failed":
			failCount++
			if e, _ := m["error"].(string); !strings.Contains(e, "429") {
				t.Fatalf("unbind ошибка без 429: %v", m["error"])
			}
		default:
			t.Fatalf("unbind: неожиданный статус %v", m["status"])
		}
	}
	if okCount != 1 || failCount != 1 {
		t.Fatalf("unbind: ok=%d failed=%d, хочу 1/1", okCount, failCount)
	}
	if !node1.isUnbound(node1.keyFor("lc-1")) || node2.isUnbound(node2.keyFor("lc-1")) {
		t.Fatal("unbind применился не так: нода 1 должна отработать, нода 2 — 429")
	}

	// 404 на несуществующей подписке.
	masterCall(t, mux, "PATCH", "/v1/master/subscriptions/999999", `{"expires_days":5}`, 404)
	masterCall(t, mux, "POST", "/v1/master/subscriptions/999999/revoke", "", 404)

	// ── Гейтинг реестра нод: админ-токен (продавец) не может ────────────────────
	masterCall(t, mux, "POST", "/v1/master/join-tokens", "", 401)
	var nodeID int64
	if err := s.db.QueryRow(`SELECT id FROM servers WHERE api=?`, node1.addr).Scan(&nodeID); err != nil {
		t.Fatal(err)
	}
	masterCall(t, mux, "DELETE", fmt.Sprintf("/v1/master/servers/%d", nodeID), "", 401)
	// …а владелец с X-Master-Token может.
	masterCallWithToken(t, mux, "DELETE", fmt.Sprintf("/v1/master/servers/%d", nodeID), "", 200, "X-Master-Token", "mtk")
}

// /peek после фикса (ss.sub_id): по user_token локального ключа (self-доставка)
// находится подписка и возвращается свежий bundle.
func TestPeekBundle(t *testing.T) {
	s, _ := newTestServer(t)
	s.cfg.Mode = masterMode
	s.cfg.AdminToken = "adm"
	mux := http.NewServeMux()
	registerRoutes(mux, s)

	// нода в реестре + подписка с одной доставкой на неё
	if _, err := s.db.Exec(`INSERT INTO servers (api, pin, master_token, name, status, last_seen, version, capacity, since)
		VALUES ('127.0.0.1:65500', ?, 'mt', 'self', 'active', 0, '', 0, 0)`, strings.Repeat("ab", 32)); err != nil {
		t.Fatal(err)
	}
	var srvID int64
	if err := s.db.QueryRow(`SELECT id FROM servers WHERE api='127.0.0.1:65500'`).Scan(&srvID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO subscriptions (external_id, name, bytes_limit, expires_at) VALUES ('peek-1', 'P', 1000, 0)`); err != nil {
		t.Fatal(err)
	}
	var subID int64
	if err := s.db.QueryRow(`SELECT id FROM subscriptions WHERE external_id='peek-1'`).Scan(&subID); err != nil {
		t.Fatal(err)
	}
	// локальный ключ с user_token (self-доставка подписки)
	if _, err := s.db.Exec(`INSERT INTO keys (id, created_at, expires_at, bytes_limit, bytes_used, user_token)
		VALUES ('loc-key-1', strftime('%s','now'), 0, 1000, 0, 'ut-self')`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO subscription_servers (sub_id, server_id, key_id, status) VALUES (?, ?, 'loc-key-1', 'active')`, subID, srvID); err != nil {
		t.Fatal(err)
	}

	peek := func(token string, want int) map[string]any {
		t.Helper()
		req := httptest.NewRequest("GET", "/v1/peek", nil)
		req.RemoteAddr = "203.0.113.50:5555"
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code != want {
			t.Fatalf("/peek: want %d, got %d: %s", want, w.Code, w.Body.String())
		}
		var out map[string]any
		json.Unmarshal(w.Body.Bytes(), &out)
		return out
	}
	out := peek("ut-self", 200)
	bundle, _ := out["bundle"].(string)
	if !strings.HasPrefix(bundle, "vkturn://bundle/") {
		t.Fatalf("peek bundle = %q", bundle)
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(bundle, "vkturn://bundle/"))
	if err != nil {
		t.Fatalf("bundle decode: %v", err)
	}
	var bp struct {
		S []struct {
			Key string `json:"key"`
		} `json:"s"`
	}
	if err := json.Unmarshal(raw, &bp); err != nil || len(bp.S) != 1 || bp.S[0].Key != "loc-key-1" {
		t.Fatalf("peek bundle payload: %+v err=%v", bp, err)
	}
	peek("wrong-token", 404)
}
