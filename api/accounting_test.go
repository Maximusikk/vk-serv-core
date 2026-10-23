package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func newTestServer(t *testing.T) (*Server, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "users"), 0750); err != nil {
		t.Fatal(err)
	}
	d, err := OpenDB(filepath.Join(dir, "api.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return NewServer(d.DB, &Config{InstallDir: dir, PortStart: 56001, PortEnd: 57000}), dir
}

func writeStats(t *testing.T, dir string, port int, start, rx, tx int64) {
	t.Helper()
	p := filepath.Join(dir, "users", itoa(port)+".stats")
	data := []byte(itoa64(start) + " " + itoa64(rx) + " " + itoa64(tx) + "\n")
	if err := os.WriteFile(p, data, 0640); err != nil {
		t.Fatal(err)
	}
}

func used(t *testing.T, s *Server, id string) int64 {
	t.Helper()
	var n int64
	if err := s.db.QueryRow(`SELECT bytes_used FROM keys WHERE id = ?`, id).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestPollTraffic(t *testing.T) {
	s, dir := newTestServer(t)
	_, err := s.db.Exec(`INSERT INTO keys (id, created_at, activated_at, expires_at, bytes_limit, port)
		VALUES ('k1', 1, 1, 0, 0, 56001)`)
	if err != nil {
		t.Fatal(err)
	}

	// Первое чтение: всё с запуска процесса считается (rx+tx — включая скачанное)
	writeStats(t, dir, 56001, 100, 1000, 500_000)
	s.pollTraffic()
	if got := used(t, s, "k1"); got != 501_000 {
		t.Fatalf("first poll: got %d want 501000", got)
	}

	// Тот же процесс: только прирост
	writeStats(t, dir, 56001, 100, 2000, 900_000)
	s.pollTraffic()
	if got := used(t, s, "k1"); got != 902_000 {
		t.Fatalf("delta: got %d want 902000", got)
	}

	// Повторное чтение без изменений — ничего не добавляется (нет двойного счёта)
	s.pollTraffic()
	if got := used(t, s, "k1"); got != 902_000 {
		t.Fatalf("idempotent: got %d want 902000", got)
	}

	// Перезапуск API (новый Server на той же БД) — состояние берётся из port_counters
	s2 := NewServer(s.db, s.cfg)
	s2.pollTraffic()
	if got := used(t, s2, "k1"); got != 902_000 {
		t.Fatalf("api restart: got %d want 902000", got)
	}

	// Перезапуск server: счётчики с нуля, новый start
	writeStats(t, dir, 56001, 200, 10, 90)
	s.pollTraffic()
	if got := used(t, s, "k1"); got != 902_100 {
		t.Fatalf("server restart: got %d want 902100", got)
	}
}

func TestPollTrafficLimitDeactivates(t *testing.T) {
	s, dir := newTestServer(t)
	_, err := s.db.Exec(`INSERT INTO keys (id, created_at, activated_at, expires_at, bytes_limit, port)
		VALUES ('k2', 1, 1, 0, 1000, 56002)`)
	if err != nil {
		t.Fatal(err)
	}
	writeStats(t, dir, 56002, 1, 600, 600)
	s.pollTraffic()

	var port *int
	_ = s.db.QueryRow(`SELECT port FROM keys WHERE id = 'k2'`).Scan(&port)
	if port != nil {
		t.Fatalf("over limit: port should be released, got %d", *port)
	}
	if _, err := os.Stat(s.statsPath(56002)); !os.IsNotExist(err) {
		t.Fatalf("stats file should be removed on deactivation")
	}
}

// Шаблон из install.sh должен совпадать с userUnitTemplate, иначе API при каждом старте
// переписывает юнит и перезапускает все порты пользователей.
func TestInstallShUnitMatchesAPI(t *testing.T) {
	data, err := os.ReadFile("../install.sh")
	if err != nil {
		t.Skip("install.sh не найден")
	}
	s := string(data)
	start := strings.Index(s, "vkserv@.service << TMPLEOF\n")
	if start < 0 {
		t.Fatal("heredoc vkserv@ не найден в install.sh")
	}
	body := s[start+len("vkserv@.service << TMPLEOF\n"):]
	body = body[:strings.Index(body, "TMPLEOF\n")]
	// Раскрываем как bash (heredoc без кавычек)
	got := strings.NewReplacer("$INSTALL_DIR", "/opt/vkturn", "$HY2_PORT", "10443", `\${WRAP_PASS}`, "${WRAP_PASS}").Replace(body)
	want := strings.NewReplacer("{DIR}", "/opt/vkturn", "{HY2}", "10443").Replace(userUnitTemplate)
	if got != want {
		t.Fatalf("install.sh и api расходятся:\n--- install.sh\n%s\n--- api\n%s", got, want)
	}
}

func itoa(n int) string     { return strconv.Itoa(n) }
func itoa64(n int64) string { return strconv.FormatInt(n, 10) }
