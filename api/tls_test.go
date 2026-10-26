package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func readFile(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read %s: %v", p, err)
	}
	return b
}

func TestEnsureCertGenerates(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tls")
	cert, err := ensureCert(dir, []string{"203.0.113.7"})
	if err != nil {
		t.Fatalf("ensureCert: %v", err)
	}
	leaf := cert.Leaf
	if leaf == nil {
		t.Fatal("Leaf не заполнен")
	}
	if pk, ok := leaf.PublicKey.(*ecdsa.PublicKey); !ok || pk.Curve != elliptic.P256() {
		t.Fatalf("ключ не ECDSA P-256: %T", leaf.PublicKey)
	}
	if leaf.PublicKeyAlgorithm != x509.ECDSA {
		t.Fatalf("алгоритм ключа %v, нужен ECDSA", leaf.PublicKeyAlgorithm)
	}
	if !strings.Contains(leaf.SignatureAlgorithm.String(), "ECDSA") {
		t.Fatalf("подпись %v", leaf.SignatureAlgorithm)
	}
	// ~10 лет
	if d := leaf.NotAfter.Sub(time.Now()); d < 9*365*24*time.Hour || d > 11*365*24*time.Hour {
		t.Fatalf("срок сертификата %v", d)
	}
	wantIPs := map[string]bool{"203.0.113.7": false, "127.0.0.1": false}
	for _, ip := range leaf.IPAddresses {
		if _, ok := wantIPs[ip.String()]; ok {
			wantIPs[ip.String()] = true
		}
	}
	for ip, ok := range wantIPs {
		if !ok {
			t.Fatalf("SAN без %s: %v", ip, leaf.IPAddresses)
		}
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "localhost" {
		t.Fatalf("DNS SAN %v", leaf.DNSNames)
	}
	if err := leaf.VerifyHostname("203.0.113.7"); err != nil {
		t.Fatalf("VerifyHostname: %v", err)
	}
}

func TestEnsureCertIdempotent(t *testing.T) {
	dir := t.TempDir()
	c1, err := ensureCert(dir, []string{"198.51.100.1"})
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := tlsPaths(dir)
	crt1, key1 := readFile(t, certPath), readFile(t, keyPath)
	st1, _ := os.Stat(certPath)

	// Другие хосты — файлы всё равно не перезаписываются
	c2, err := ensureCert(dir, []string{"192.0.2.99"})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(crt1, readFile(t, certPath)) || !bytes.Equal(key1, readFile(t, keyPath)) {
		t.Fatal("повторный вызов изменил файлы")
	}
	st2, _ := os.Stat(certPath)
	if !st1.ModTime().Equal(st2.ModTime()) {
		t.Fatal("повторный вызов перезаписал api.crt")
	}
	if spkiPin(c1.Leaf) != spkiPin(c2.Leaf) {
		t.Fatal("пин изменился между вызовами")
	}
}

func TestEnsureCertHalfPairFails(t *testing.T) {
	dir := t.TempDir()
	if _, err := ensureCert(dir, nil); err != nil {
		t.Fatal(err)
	}
	_, keyPath := tlsPaths(dir)
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	if _, err := ensureCert(dir, nil); err == nil {
		t.Fatal("ожидалась ошибка при наличии только api.crt")
	}
}

func TestSpkiPinManual(t *testing.T) {
	dir := t.TempDir()
	cert, err := ensureCert(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	pin := spkiPin(cert.Leaf)
	if len(pin) != 64 || strings.ToLower(pin) != pin {
		t.Fatalf("пин не строчный hex 64: %q", pin)
	}
	if _, err := hex.DecodeString(pin); err != nil {
		t.Fatalf("пин не hex: %v", err)
	}
	// Ручной расчёт: из PEM-файла → x509 → MarshalPKIXPublicKey → SHA-256
	certPath, _ := tlsPaths(dir)
	block, _ := pem.Decode(readFile(t, certPath))
	if block == nil {
		t.Fatal("api.crt не PEM")
	}
	parsed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(parsed.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(spki)
	if want := hex.EncodeToString(sum[:]); pin != want {
		t.Fatalf("пин %s != ручной %s", pin, want)
	}
	if spkiPin(parsed) != pin {
		t.Fatal("пин нестабилен")
	}
}

func TestEnsureCertPermissions(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("права файлов проверяются только на Linux")
	}
	dir := filepath.Join(t.TempDir(), "tls")
	if _, err := ensureCert(dir, nil); err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := tlsPaths(dir)
	check := func(p string, want os.FileMode) {
		st, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if got := st.Mode().Perm(); got != want {
			t.Fatalf("%s: права %o, нужно %o", p, got, want)
		}
	}
	check(dir, 0o700)
	check(certPath, 0o644)
	check(keyPath, 0o600)
}

func TestHostFromPublicURL(t *testing.T) {
	cases := map[string]string{
		"":                      "",
		"1.2.3.4:7000":          "1.2.3.4",
		"https://1.2.3.4:7000/": "1.2.3.4",
		"example.com":           "example.com",
		"[2001:db8::1]:7000":    "2001:db8::1",
	}
	for in, want := range cases {
		if got := hostFromPublicURL(in); got != want {
			t.Errorf("hostFromPublicURL(%q) = %q, want %q", in, got, want)
		}
	}
}

var errPinMismatch = errors.New("pin mismatch")

// pinnedClient — клиент, доверяющий серверу только по SPKI-пину (как приложения/бот).
func pinnedClient(pin string) *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion:         tls.VersionTLS12,
				InsecureSkipVerify: true, // цепочку заменяет проверка пина ниже
				VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
					if len(raw) == 0 {
						return errPinMismatch
					}
					leaf, err := x509.ParseCertificate(raw[0])
					if err != nil {
						return err
					}
					if spkiPin(leaf) != pin {
						return errPinMismatch
					}
					return nil
				},
			},
		},
	}
}

func startPinnedTestServer(t *testing.T) (*httptest.Server, string, *bool) {
	t.Helper()
	cert, err := ensureCert(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	hit := new(bool)
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*hit = true
		_, _ = io.WriteString(w, "ok")
	}))
	ts.TLS = serverTLSConfig(cert)
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return ts, spkiPin(cert.Leaf), hit
}

func TestPinnedClientAccepts(t *testing.T) {
	ts, pin, hit := startPinnedTestServer(t)
	resp, err := pinnedClient(pin).Get(ts.URL)
	if err != nil {
		t.Fatalf("запрос с верным пином: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "ok" || !*hit {
		t.Fatalf("ответ %q, hit=%v", body, *hit)
	}
	if resp.TLS == nil || resp.TLS.Version < tls.VersionTLS12 {
		t.Fatal("ожидался TLS >= 1.2")
	}
}

func TestPinnedClientRejectsWrongPin(t *testing.T) {
	ts, pin, hit := startPinnedTestServer(t)
	wrong := strings.Repeat("0", 64)
	if wrong == pin {
		t.Fatal("невероятно")
	}
	_, err := pinnedClient(wrong).Post(ts.URL, "application/json", strings.NewReader(`{"key":"SECRET"}`))
	if err == nil {
		t.Fatal("запрос с чужим пином прошёл")
	}
	if !errors.Is(err, errPinMismatch) && !strings.Contains(err.Error(), "pin mismatch") {
		t.Fatalf("неожиданная ошибка: %v", err)
	}
	if *hit {
		t.Fatal("обработчик получил запрос при неверном пине")
	}
}

func TestServerRejectsTLS11(t *testing.T) {
	ts, _, _ := startPinnedTestServer(t)
	conn, err := tls.Dial("tcp", ts.Listener.Addr().String(), &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS11,
	})
	if err == nil {
		conn.Close()
		t.Fatal("сервер принял TLS 1.1")
	}
}

func TestPlainHTTPNotServed(t *testing.T) {
	ts, _, hit := startPinnedTestServer(t)
	addr := ts.Listener.Addr().String()
	c := &http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get("http://" + addr + "/")
	if err == nil {
		defer resp.Body.Close()
		// Go TLS-сервер отвечает на HTTP «400 Client sent an HTTP request to an HTTPS server»
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("HTTP получил %d", resp.StatusCode)
		}
	}
	if *hit {
		t.Fatal("обработчик получил plain-HTTP запрос")
	}
}
