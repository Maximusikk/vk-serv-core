package main

import (
	"context"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"
)

const (
	defaultPortStart  = 56001
	defaultPortEnd    = 57000
	defaultInstallDir = "/opt/vkturn"
	defaultHy2Port    = 10443
)

// Config — параметры запуска (флаги + переменные окружения).
type Config struct {
	DBPath         string
	BindAddr       string
	ListenPort     string
	AdminToken     string
	InternalSecret string
	PortStart      int
	PortEnd        int
	InstallDir     string
	Hy2Port        int
	PublicURL      string // публичный адрес API для ссылок vkturn://key/<host>/<KEY>, напр. example.com:7000

	ActivateRate int // запросов /activate в минуту с одного IP (rate limit B5)
	UnbindDays   int // мин. дней между unbind одного ключа (G6); 0 = без ограничения
	MaxActive    int // максимум живых vkserv@ (G3); 0 = без ограничения (весь диапазон портов)

	AdminAllow     string       // список IP/CIDR, с которых разрешён /admin/* (D2); пусто = без ограничения
	AdminAllowNets []*net.IPNet // разобранный AdminAllow

	NotifyURL string // webhook продавца для уведомлений (G5); пусто = выключено

	ReconcileInterval time.Duration // период reconcile-цикла портов (1.3); 0 = дефолт 20 с

	TLSDir string // каталог api.crt/api.key (S1); по умолчанию /opt/vkturn/tls
	TLSPin string // SPKI-пин сертификата API: hex SHA-256, 64 символа (не секрет)
}

// envInt читает целочисленную переменную окружения (0 при отсутствии/ошибке).
func envInt(name string) int {
	n, _ := strconv.Atoi(os.Getenv(name))
	return n
}

func main() {
	cfg := &Config{}
	flag.StringVar(&cfg.DBPath, "db", "/opt/vkturn/api.db", "путь к SQLite базе")
	flag.StringVar(&cfg.BindAddr, "bind", "127.0.0.1", "адрес для прослушивания (0.0.0.0 — все интерфейсы)")
	flag.StringVar(&cfg.ListenPort, "port", "7000", "порт прослушивания")
	flag.StringVar(&cfg.AdminToken, "admin-token", os.Getenv("ADMIN_TOKEN"), "токен для /admin/*")
	flag.StringVar(&cfg.InternalSecret, "internal-secret", os.Getenv("INTERNAL_SECRET"), "секрет для /internal/*")
	flag.IntVar(&cfg.PortStart, "port-start", defaultPortStart, "начало диапазона портов vkserv")
	flag.IntVar(&cfg.PortEnd, "port-end", defaultPortEnd, "конец диапазона портов vkserv")
	flag.StringVar(&cfg.InstallDir, "dir", defaultInstallDir, "каталог установки VKTurn")
	flag.IntVar(&cfg.Hy2Port, "hy2-port", defaultHy2Port, "порт hysteria2 бэкенда")
	flag.StringVar(&cfg.PublicURL, "public-url", os.Getenv("PUBLIC_URL"), "публичный адрес API для ссылок (напр. example.com:7000)")
	flag.IntVar(&cfg.ActivateRate, "activate-rate", activateRateLimit, "лимит /activate с одного IP в минуту")
	unbindDays := 7
	if v := envInt("UNBIND_DAYS"); v > 0 {
		unbindDays = v
	}
	flag.IntVar(&cfg.UnbindDays, "unbind-days", unbindDays, "минимум дней между unbind одного ключа (0 = без ограничения)")
	maxActive := envInt("MAX_ACTIVE")
	flag.IntVar(&cfg.MaxActive, "max-active", maxActive, "максимум живых портов vkserv (0 = без ограничения)")
	flag.StringVar(&cfg.AdminAllow, "admin-allow", os.Getenv("ADMIN_ALLOW"), "IP/CIDR через запятую, с которых разрешён /admin/* (пусто = с любого IP)")
	flag.StringVar(&cfg.NotifyURL, "notify-url", os.Getenv("NOTIFY_URL"), "webhook для уведомлений продавцу: VK-ссылка умерла, диск/порты на исходе (пусто = выключено)")
	// 1.3: период reconcile-цикла; env RECONCILE_INTERVAL (секунды) как альтернатива флагу
	reconcileSec := envInt("RECONCILE_INTERVAL")
	flag.DurationVar(&cfg.ReconcileInterval, "reconcile-interval", time.Duration(reconcileSec)*time.Second, "период reconcile-цикла портов (напр. 20s; 0 = дефолт 20s)")
	tlsDir := os.Getenv("TLS_DIR")
	if tlsDir == "" {
		tlsDir = defaultTLSDir
	}
	flag.StringVar(&cfg.TLSDir, "tls-dir", tlsDir, "каталог TLS-сертификата API (api.crt/api.key; создаётся при первом старте)")
	flag.Parse()

	nets, err := parseAllowList(cfg.AdminAllow)
	if err != nil {
		log.Fatalf("-admin-allow: %v", err)
	}
	cfg.AdminAllowNets = nets

	if cfg.AdminToken == "" {
		log.Fatal("ADMIN_TOKEN не задан (флаг -admin-token или переменная ADMIN_TOKEN)")
	}
	if cfg.InternalSecret == "" {
		log.Fatal("INTERNAL_SECRET не задан (флаг -internal-secret или переменная INTERNAL_SECRET)")
	}

	// TLS (S1): сертификат создаётся при первом старте, без него API не запускается
	var certHosts []string
	if h := hostFromPublicURL(cfg.PublicURL); h != "" {
		certHosts = append(certHosts, h)
	}
	if ip := net.ParseIP(cfg.BindAddr); ip != nil && !ip.IsUnspecified() {
		certHosts = append(certHosts, cfg.BindAddr)
	}
	cert, err := ensureCert(cfg.TLSDir, certHosts)
	if err != nil {
		log.Fatalf("TLS: не удалось создать или прочитать сертификат в %s: %v (проверьте права каталога или флаг -tls-dir / TLS_DIR)", cfg.TLSDir, err)
	}
	cfg.TLSPin = spkiPin(cert.Leaf)

	sqlDB, err := OpenDB(cfg.DBPath)
	if err != nil {
		log.Fatalf("БД: %v", err)
	}
	defer sqlDB.Close()

	srv := NewServer(sqlDB.DB, cfg)

	// Шаблон vkserv@ с учётом трафика + iptables после перезагрузки, затем фоновые циклы:
	// учёт трафика и гашение ключей с истёкшим сроком
	srv.ensureUserUnits()
	go srv.runTrafficPoller(context.Background())
	go srv.runExpiryTicker(context.Background())
	go srv.runNotifyChecker(context.Background())
	go srv.runReconciler(context.Background()) // 1.3: сверка портов с реальностью

	mux := http.NewServeMux()
	registerRoutes(mux, srv)

	addr := net.JoinHostPort(cfg.BindAddr, cfg.ListenPort)
	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    16 << 10,
		TLSConfig:         serverTLSConfig(cert),
	}
	log.Printf("vkturn-api: слушаю https://%s (db=%s, порты %d..%d, dir=%s, tls-dir=%s)",
		addr, cfg.DBPath, cfg.PortStart, cfg.PortEnd, cfg.InstallDir, cfg.TLSDir)
	log.Printf("vkturn-api: TLS_PIN=%s", cfg.TLSPin)
	// Сертификат уже в TLSConfig — пути пустые
	log.Fatal(httpSrv.ListenAndServeTLS("", ""))
}

func nowUnix() int64 { return time.Now().Unix() }
