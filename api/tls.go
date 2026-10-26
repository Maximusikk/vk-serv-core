package main

// TLS для vkturn-api (S1, контракт §1 SECURITY_TLS_PLAN.md):
// самоподписанный сертификат ECDSA P-256 на 10 лет, генерируется при первом старте,
// клиенты сверяют SPKI-пин (SHA-256 от DER SubjectPublicKeyInfo, строчный hex).

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	defaultTLSDir   = "/opt/vkturn/tls"
	tlsCertFile     = "api.crt"
	tlsKeyFile      = "api.key"
	tlsCertValidity = 10 * 365 * 24 * time.Hour
)

// tlsPaths — пути к сертификату и ключу в каталоге dir.
func tlsPaths(dir string) (certPath, keyPath string) {
	return filepath.Join(dir, tlsCertFile), filepath.Join(dir, tlsKeyFile)
}

// ensureCert идемпотентно обеспечивает наличие сертификата в dir и загружает его.
// Если оба файла есть — они только читаются (не перезаписываются). Если нет ни одного —
// генерируется новый ECDSA P-256 сертификат на 10 лет с SAN = hosts + 127.0.0.1 + localhost.
// Если есть только один из файлов — ошибка (не затираем чужой ключ/сертификат).
// Права: каталог 0700, api.crt 0644, api.key 0600.
func ensureCert(dir string, hosts []string) (tls.Certificate, error) {
	if dir == "" {
		return tls.Certificate{}, errors.New("каталог TLS не задан")
	}
	certPath, keyPath := tlsPaths(dir)
	certExists, err := fileExists(certPath)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyExists, err := fileExists(keyPath)
	if err != nil {
		return tls.Certificate{}, err
	}
	switch {
	case certExists && keyExists:
		return loadCert(certPath, keyPath)
	case certExists != keyExists:
		return tls.Certificate{}, fmt.Errorf("в %s есть только один из файлов %s/%s — восстановите пару или удалите оба", dir, tlsCertFile, tlsKeyFile)
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return tls.Certificate{}, fmt.Errorf("создание каталога %s: %w", dir, err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return tls.Certificate{}, fmt.Errorf("права каталога %s: %w", dir, err)
	}
	certPEM, keyPEM, err := generateCert(hosts)
	if err != nil {
		return tls.Certificate{}, err
	}
	// Сначала ключ, потом сертификат: O_EXCL — не перезаписываем, если файл появился параллельно.
	if err := writeNewFile(keyPath, keyPEM, 0o600); err != nil {
		return tls.Certificate{}, err
	}
	if err := writeNewFile(certPath, certPEM, 0o644); err != nil {
		_ = os.Remove(keyPath)
		return tls.Certificate{}, err
	}
	return loadCert(certPath, keyPath)
}

func fileExists(p string) (bool, error) {
	_, err := os.Stat(p)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, fmt.Errorf("проверка %s: %w", p, err)
}

func writeNewFile(p string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return fmt.Errorf("создание %s: %w", p, err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		_ = os.Remove(p)
		return fmt.Errorf("запись %s: %w", p, err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(p)
		return fmt.Errorf("запись %s: %w", p, err)
	}
	// umask мог урезать права при создании — выставляем явно
	if err := os.Chmod(p, perm); err != nil {
		return fmt.Errorf("права %s: %w", p, err)
	}
	return nil
}

// generateCert создаёт самоподписанный сертификат (PEM) и ключ (PEM, PKCS#8).
func generateCert(hosts []string) (certPEM, keyPEM []byte, err error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("генерация ключа: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("серийный номер: %w", err)
	}
	ips, dns := sanFromHosts(hosts)
	cn := "vkturn-api"
	if len(ips) > 0 {
		cn = ips[0].String()
	} else if len(dns) > 0 {
		cn = dns[0]
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"VKTurn"}},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.Add(tlsCertValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           ips,
		DNSNames:              dns,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, fmt.Errorf("создание сертификата: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("кодирование ключа: %w", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

// sanFromHosts — IP и DNS-имена для SAN: переданные хосты + 127.0.0.1 + localhost, без дублей.
func sanFromHosts(hosts []string) ([]net.IP, []string) {
	var ips []net.IP
	var dns []string
	seen := map[string]bool{}
	for _, h := range append(append([]string{}, hosts...), "127.0.0.1", "localhost") {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if ip := net.ParseIP(h); ip != nil {
			if v4 := ip.To4(); v4 != nil {
				ip = v4
			}
			k := "ip:" + ip.String()
			if !seen[k] {
				seen[k] = true
				ips = append(ips, ip)
			}
			continue
		}
		k := "dns:" + strings.ToLower(h)
		if !seen[k] {
			seen[k] = true
			dns = append(dns, strings.ToLower(h))
		}
	}
	return ips, dns
}

// hostFromPublicURL извлекает хост из PUBLIC_URL ("1.2.3.4:7000", "https://host:7000/", "[::1]:7000").
func hostFromPublicURL(u string) string {
	u = strings.TrimSpace(u)
	if i := strings.Index(u, "://"); i >= 0 {
		u = u[i+3:]
	}
	if i := strings.IndexAny(u, "/?#"); i >= 0 {
		u = u[:i]
	}
	if h, _, err := net.SplitHostPort(u); err == nil {
		return h
	}
	return strings.Trim(u, "[]")
}

// loadCert читает пару и заполняет Leaf.
func loadCert(certPath, keyPath string) (tls.Certificate, error) {
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("чтение %s/%s: %w", certPath, keyPath, err)
	}
	if pair.Leaf == nil {
		leaf, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("разбор %s: %w", certPath, err)
		}
		pair.Leaf = leaf
	}
	return pair, nil
}

// spkiPin — SHA-256 от DER SubjectPublicKeyInfo сертификата, строчный hex (64 символа).
// Для curl: --pinnedpubkey sha256//<base64 того же хэша>.
func spkiPin(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

// serverTLSConfig — TLS-конфиг сервера: TLS 1.2+, шифры по умолчанию Go.
func serverTLSConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
	}
}
