#!/bin/bash
# VKTurn — автоустановка сервера на голый VPS
# Поддерживается: Ubuntu 20.04+, Debian 10+, x86_64 / arm64
#
# Использование:
#   curl -s https://raw.githubusercontent.com/Maximusikk/vk-serv-core/main/install.sh | bash
#   или: bash install.sh

set -euo pipefail

# ── Цвета ─────────────────────────────────────────────────────────────────────
R='\033[0;31m' G='\033[0;32m' Y='\033[1;33m' B='\033[0;34m' W='\033[1m' N='\033[0m'

info()  { echo -e "${G}[+]${N} $*"; }
warn()  { echo -e "${Y}[!]${N} $*"; }
error() { echo -e "${R}[✗]${N} $*"; exit 1; }
step()  { echo -e "\n${W}━━━ $* ━━━${N}"; }

# ── Константы ─────────────────────────────────────────────────────────────────
# Версия закреплена: /latest указывает на релиз v1.0.0-user-only, где только APK (серверных бинарников нет)
VKSERV_VERSION="${VKSERV_VERSION:-v1.3.0-server-binary}"
VKSERV_REPO="https://github.com/Maximusikk/vk-serv-core/releases/download/$VKSERV_VERSION"
# Hysteria закреплена конкретной версией (F5): /latest может принести несовместимый релиз.
HY2_VERSION="${HY2_VERSION:-app/v2.12.2}"
HY2_REPO="https://github.com/apernet/hysteria/releases/download/$HY2_VERSION"
INSTALL_DIR="/opt/vkturn"
LOG_DIR="/var/log/vkturn"
VKSERV_PORT=56000
HY2_PORT=10443
API_PORT=7000

# ── Роль установки (3.8) ──────────────────────────────────────────────────────
# ROLE=node (по умолчанию) | master | master+node
#   node        — релейная нода (как раньше): hysteria2 + vkserv + api (режим ноды)
#   master      — чистый админ-сервер: только api в режиме мастера (без hy2/vkserv/56000)
#   master+node — то же, что node, но api работает в режиме мастера и как нода
ROLE="${ROLE:-node}"
case "$ROLE" in
  node)        API_MODE="node";   IS_MASTER=0; NODE_INSTALL=1 ;;
  master)      API_MODE="master"; IS_MASTER=1; NODE_INSTALL=0 ;;
  master+node) API_MODE="master"; IS_MASTER=1; NODE_INSTALL=1 ;;
  *) error "ROLE=$ROLE не поддерживается. Допустимо: node | master | master+node" ;;
esac

# 3.7: подключение ноды к мастеру (только для установок с нодой).
# JOIN_URL или JOIN — адрес мастера вида https://<мастер>:7000.
JOIN_URL="${JOIN_URL:-${JOIN:-}}"
# JOIN_TOKEN — одноразовый токен с мастера (POST /v1/master/join-tokens).
# JOIN_PIN — hex64 SPKI-пин сертификата МАСТЕРА (правило «пин до токена»).
JOIN_TOKEN="${JOIN_TOKEN:-}"
JOIN_PIN="${JOIN_PIN:-}"
JOIN_CAPACITY="${JOIN_CAPACITY:-100}"

# ── Проверка root ──────────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && error "Запускай от root: sudo bash install.sh"

# verify_sha256 FILE ASSET — обязательная проверка по SHA256SUMS из релиза vkserv (F5).
# Проверка обязательна, обхода нет: если SHA256SUMS не скачался или в нём нет записи
# для ассета — это ошибка установки (fail-closed), а не молчаливый пропуск.
verify_sha256() {
    local file="$1" asset="$2"
    local sums want got
    sums=$(mktemp)
    if ! wget -q -O "$sums" "$VKSERV_REPO/SHA256SUMS" 2>/dev/null; then
        rm -f "$sums"
        error "$asset: не удалось скачать SHA256SUMS из релиза $VKSERV_VERSION — проверка целостности обязательна. Установка прервана; если релиз опубликован без SHA256SUMS, сообщите об этом."
    fi
    want=$(awk -v f="$asset" '{sub(/^\*/,"",$2)} $2==f{print $1}' "$sums" || true)
    got=$(sha256sum "$file" | awk '{print $1}')
    if [ -z "$want" ]; then
        rm -f "$sums"
        error "$asset: нет записи в SHA256SUMS релиза — проверка целостности обязательна"
    fi
    if [ "$want" != "$got" ]; then
        rm -f "$sums"
        error "$asset: не совпал SHA-256 (ожидалось $want, получено $got) — файл релиза повреждён?"
    fi
    rm -f "$sums"
    info "$asset: SHA-256 сверён"
}

# download URL OUT [MIN_BYTES] — curl с повторами, затем wget; без --show-progress (ломается на старых wget).
# Любая ошибка даёт понятное сообщение (раньше set -e молча обрывал скрипт).
download() {
    local url="$1" out="$2" min="${3:-100000}" i size
    for i in 1 2 3 4; do
        rm -f "$out"
        if command -v curl >/dev/null 2>&1 && curl -fL --connect-timeout 15 --max-time 600 -sS -o "$out" "$url" 2>/tmp/vkturn-dl.err; then :
        elif wget -q -T 30 -t 2 -O "$out" "$url" 2>>/tmp/vkturn-dl.err; then :
        else
            warn "Загрузка не удалась (попытка $i/4): $(tail -n1 /tmp/vkturn-dl.err 2>/dev/null)"
            sleep $((i * 3)); continue
        fi
        size=$(stat -c %s "$out" 2>/dev/null || echo 0)
        if [ "$size" -ge "$min" ]; then rm -f /tmp/vkturn-dl.err; return 0; fi
        warn "Файл слишком мал ($size байт), попытка $i/4"
        sleep $((i * 3))
    done
    rm -f "$out"
    error "Не удалось скачать $url — проверь доступ VPS к github.com (curl -I https://github.com), DNS и время сервера"
}

# ── Guard от переустановки ─────────────────────────────────────────────────────
if [ -f "$INSTALL_DIR/config.txt" ]; then
  if [ "${FORCE_REINSTALL:-}" != "1" ]; then
    error "Сервер уже установлен в $INSTALL_DIR. Для переустановки используйте FORCE_REINSTALL=1 bash install.sh"
  fi
  warn "FORCE_REINSTALL=1: создаём бэкап..."
  BACKUP_DIR="$INSTALL_DIR/backup-$(date +%Y%m%d_%H%M%S)"
  mkdir -p "$BACKUP_DIR"
  cp -a "$INSTALL_DIR/config.txt" "$INSTALL_DIR/api.db" "$INSTALL_DIR/users" "$BACKUP_DIR/" 2>/dev/null || true
  info "Бэкап создан: $BACKUP_DIR"
fi

# ── ОС и архитектура ──────────────────────────────────────────────────────────
step "Проверка системы"
ARCH=$(uname -m)
case "$ARCH" in
  x86_64)  ARCH_SUFFIX="amd64" ;;
  aarch64) ARCH_SUFFIX="arm64" ;;
  *) error "Неподдерживаемая архитектура: $ARCH" ;;
esac

if ! command -v apt-get &>/dev/null; then
  error "Поддерживается только Ubuntu/Debian (apt)"
fi

# Публичный IP: приоритет env (передан из приложения) → автоопределение
if [ -z "${SERVER_IP:-}" ]; then
    SERVER_IP=$(curl -s4 https://api.ipify.org 2>/dev/null || curl -s4 https://ifconfig.me 2>/dev/null || true)
fi
[ -z "$SERVER_IP" ] && error "Не удалось определить IP. Передай SERVER_IP=твой_IP"

info "ОС: $(grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '\"')"
info "Архитектура: $ARCH ($ARCH_SUFFIX)"
info "Публичный IP: $SERVER_IP"

# ── Зависимости ───────────────────────────────────────────────────────────────
step "Установка зависимостей"
apt-get update -qq
apt-get install -y -qq curl wget openssl ufw qrencode sqlite3 2>/dev/null || \
  apt-get install -y -qq curl wget openssl ufw sqlite3 2>/dev/null
info "Зависимости установлены"

# ── Генерация паролей ─────────────────────────────────────────────────────────
step "Генерация конфигурации"
WRAP_PASS=$(openssl rand -hex 16)
HY2_PASS=$(openssl rand -hex 16)
SERVER_NAME="VKTurn-$(hostname | cut -c1-8)"

# Токены API — генерируем всегда
ADMIN_TOKEN=$(openssl rand -hex 24)
MASTER_TOKEN=$(openssl rand -hex 24)
INTERNAL_SECRET=$(openssl rand -hex 24)
PORT_START=56001
PORT_END=57000

# Пароли в stdout НЕ печатаем (F10): вывод попадает в SSH-лог админки. Они лежат в config.txt (600)
# и зашиты в итоговую ссылку vkturn://.
info "Пароли сгенерированы (сохраняются в $INSTALL_DIR/config.txt)"

# ── Ввод VK ссылки (только для установок с нодой) ────────────────────────────
step "VK звонок"
if [ "$NODE_INSTALL" = "1" ]; then
echo ""
echo -e "${Y}Создай звонок в VK:${N}"
echo "  1. Открой ВКонтакте → Звонки → Создать звонок → Конференция"
echo "  2. БЕЗ пароля"
echo "  3. Скопируй ссылку вида https://vk.com/call/join/ХХХХ"
echo ""
if [ -z "${VK_LINK:-}" ]; then
    # При `curl | bash` stdin занят скриптом — читаем с терминала напрямую.
    # Проверяем реальную возможность открыть /dev/tty (в SSH без pty он есть, но не открывается).
    if { : </dev/tty; } 2>/dev/null; then
        read -rp "Вставь ссылку VK звонка: " VK_LINK </dev/tty
    else
        error "Нет терминала для ввода и не задана VK_LINK. Запусти так: VK_LINK='https://vk.com/call/join/XXXX' bash install.sh"
    fi
fi
# Строгая проверка (F8): тот же формат, что в api/health.go и update-vk.sh.
# Гарантирует безопасную запись в config.txt: без пробелов, переводов строк, $ и `.
echo "$VK_LINK" | grep -qE '^https://vk\.(com|ru)/call/join/[A-Za-z0-9_-]+$' || error "Неверная ссылка. Ожидается https://vk.com/call/join/XXXX (латиница, цифры, _ или -)"
info "VK ссылка принята"
else
    # Чистый мастер не раздаёт пользовательские конфиги — VK ссылка не нужна.
    VK_LINK=""
    info "Режим $ROLE: VK ссылка не требуется"
fi

# ── Остановка старых сервисов (при переустановке) ────────────────────────────
for _svc in vkturn-api vkturn-server vkturn-hy2; do
    systemctl stop "$_svc" 2>/dev/null || true
done
sleep 1

# ── Директории ────────────────────────────────────────────────────────────────
step "Создание директорий"
mkdir -p "$INSTALL_DIR" "$INSTALL_DIR/users" "$LOG_DIR"
chmod 755 "$INSTALL_DIR"
# Каталог TLS vkturn-api: сам API создаёт его при первом старте (S1: ensureCert),
# здесь создаём заранее с правами 700 — ключ и сертификат не должны быть доступны другим юзерам.
mkdir -p "$INSTALL_DIR/tls"
chmod 700 "$INSTALL_DIR/tls"

# Логи не должны съесть диск (F7)
cat > /etc/logrotate.d/vkturn << EOF
$LOG_DIR/*.log {
    daily
    rotate 7
    maxsize 20M
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
EOF

# ── Скачивание vkserv (только нода) ───────────────────────────────────────────
if [ "$NODE_INSTALL" = "1" ]; then
step "Загрузка vkserv"
download "$VKSERV_REPO/server-linux-$ARCH_SUFFIX" "$INSTALL_DIR/server"
chmod +x "$INSTALL_DIR/server"
verify_sha256 "$INSTALL_DIR/server" "server-linux-$ARCH_SUFFIX"
info "vkserv OK"
fi

# ── Скачивание hysteria2 (только нода) ────────────────────────────────────────
if [ "$NODE_INSTALL" = "1" ]; then
step "Загрузка hysteria2 ($HY2_VERSION)"
download "$HY2_REPO/hysteria-linux-$ARCH_SUFFIX" "$INSTALL_DIR/hysteria2" 1000000
chmod +x "$INSTALL_DIR/hysteria2"
# У hysteria свой SHA256SUMS.txt в каждом релизе — проверяем обязательно
if wget -q -O "$INSTALL_DIR/.hy2.sha256" "$HY2_REPO/SHA256SUMS.txt" 2>/dev/null; then
    WANT=$(awk -v f="hysteria-linux-$ARCH_SUFFIX" '{sub(/^\*/,"",$2)} $2==f{print $1}' "$INSTALL_DIR/.hy2.sha256" || true)
    GOT=$(sha256sum "$INSTALL_DIR/hysteria2" | awk '{print $1}')
    if [ -n "$WANT" ] && [ "$WANT" != "$GOT" ]; then
        rm -f "$INSTALL_DIR/.hy2.sha256"
        error "hysteria2: не совпал SHA-256 (ожидалось $WANT, получено $GOT)"
    fi
    rm -f "$INSTALL_DIR/.hy2.sha256"
    info "hysteria2 OK (SHA-256 сверён)"
else
    info "hysteria2 OK (SHA256SUMS.txt недоступен — сверить вручную: https://github.com/apernet/hysteria/releases/tag/$HY2_VERSION)"
fi
fi

# ── API сервер подписок ───────────────────────────────────────────────────────
step "Загрузка API сервера подписок"
API_URL="$VKSERV_REPO/vkturn-api-$ARCH_SUFFIX"
API_INSTALLED=0
if curl -fsIL --connect-timeout 15 "$API_URL" >/dev/null 2>&1 || wget -q --spider "$API_URL" 2>/dev/null; then
    download "$API_URL" "$INSTALL_DIR/api"
    chmod +x "$INSTALL_DIR/api"
    verify_sha256 "$INSTALL_DIR/api" "vkturn-api-$ARCH_SUFFIX"
    # TLS обязателен (контракт): API слушает только HTTPS, нужен флаг -tls-dir (как в upgrade.sh)
    API_HELP=$("$INSTALL_DIR/api" -h 2>&1 || true)
    grep -- "-tls-dir" <<<"$API_HELP" >/dev/null || \
        error "Скачанный vkturn-api без -tls-dir — в релизе $VKSERV_VERSION нет TLS-сборки"
    API_INSTALLED=1
    info "vkturn-api OK (TLS)"
else
    warn "vkturn-api не найден в releases — админка недоступна (токены всё равно сохранены)"
fi

# ── TLS сертификат для hysteria2 (только нода; vkturn-api создаёт свой в $INSTALL_DIR/tls сам при первом старте) ──
if [ "$NODE_INSTALL" = "1" ]; then
step "Генерация TLS сертификата"
openssl req -x509 -newkey ec \
  -pkeyopt ec_paramgen_curve:P-256 \
  -keyout "$INSTALL_DIR/key.pem" \
  -out    "$INSTALL_DIR/cert.pem" \
  -days   3650 -nodes \
  -subj   "/CN=$SERVER_IP" \
  -addext "subjectAltName=IP:$SERVER_IP" 2>/dev/null
chmod 640 "$INSTALL_DIR/key.pem"
info "Сертификат создан (10 лет)"
fi

# ── Конфиг hysteria2 (только нода) ────────────────────────────────────────────
if [ "$NODE_INSTALL" = "1" ]; then
step "Конфигурация hysteria2"
cat > "$INSTALL_DIR/hy2.yaml" << EOF
listen: 127.0.0.1:$HY2_PORT

tls:
  cert: $INSTALL_DIR/cert.pem
  key:  $INSTALL_DIR/key.pem

auth:
  type: password
  password: "$HY2_PASS"

masquerade:
  type: proxy
  proxy:
    url: https://www.bing.com/
    rewriteHost: true
EOF
chmod 600 "$INSTALL_DIR/hy2.yaml"   # 0.12: внутри пароль hysteria2
# 0.12: api.db может существовать при переустановке — новый файл создаст сам API под UMask=0077
[ -f "$INSTALL_DIR/api.db" ] && chmod 600 "$INSTALL_DIR/api.db"
fi

# ── Systemd сервисы ───────────────────────────────────────────────────────────
step "Настройка systemd"

if [ "$NODE_INSTALL" = "1" ]; then
# hysteria2
cat > /etc/systemd/system/vkturn-hy2.service << EOF
[Unit]
Description=VKTurn hysteria2 backend
After=network.target

[Service]
Type=simple
ExecStart=$INSTALL_DIR/hysteria2 server -c $INSTALL_DIR/hy2.yaml
Restart=always
RestartSec=3
StandardOutput=append:$LOG_DIR/hy2.log
StandardError=append:$LOG_DIR/hy2.log

[Install]
WantedBy=multi-user.target
EOF

# vkserv (основной, для прямого подключения)
cat > /etc/systemd/system/vkturn-server.service << EOF
[Unit]
Description=VKTurn server (TURN relay)
After=network.target vkturn-hy2.service

[Service]
Type=simple
ExecStart=$INSTALL_DIR/server \\
  -listen 0.0.0.0:$VKSERV_PORT \\
  -connect 127.0.0.1:$HY2_PORT \\
  -wrap \\
  -password "$WRAP_PASS"
Restart=always
RestartSec=3
StandardOutput=append:$LOG_DIR/server.log
StandardError=append:$LOG_DIR/server.log

[Install]
WantedBy=multi-user.target
EOF

# vkserv@PORT — шаблон для персональных подключений по ключу.
# -stats-file: server сам считает байты в обе стороны, vkturn-api читает и ведёт учёт.
# Текст должен совпадать с userUnitTemplate в api/accounting.go (иначе API перепишет его при старте).
cat > /etc/systemd/system/vkserv@.service << TMPLEOF
[Unit]
Description=VKTurn user relay port %i
After=network.target

[Service]
Type=simple
EnvironmentFile=$INSTALL_DIR/users/%i.conf
ExecStart=$INSTALL_DIR/server -listen 0.0.0.0:%i -connect 127.0.0.1:$HY2_PORT -wrap -password \${WRAP_PASS} -stats-file $INSTALL_DIR/users/%i.stats
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
TMPLEOF
fi

# API сервер (если скачался). Токены — в EnvironmentFile (F4): не светятся в
# ExecStart (видны в systemctl show / ps), а отдельный файл ставится 600.
if [ "$API_INSTALLED" = "1" ]; then
    # ALSO_NODE=1 — только для master+node (нода подмастерье у самой себя)
    ALSO_NODE_LINE=""
    [ "$ROLE" = "master+node" ] && ALSO_NODE_LINE="1"
    umask 077
    cat > $INSTALL_DIR/api.env << EOF
ADMIN_TOKEN=$ADMIN_TOKEN
MASTER_TOKEN=$MASTER_TOKEN
INTERNAL_SECRET=$INTERNAL_SECRET
PUBLIC_URL=$SERVER_IP:$API_PORT
MODE=$API_MODE
${ALSO_NODE_LINE:+ALSO_NODE=1}
${NOTIFY_URL:+NOTIFY_URL=$NOTIFY_URL}
EOF
    chmod 600 $INSTALL_DIR/api.env
    umask 022
    # Токены не попадают в ExecStart (0.11: видны в ps) — API берёт их из api.env
    # (дефолты флагов -admin-token/-internal-secret = переменные ADMIN_TOKEN/INTERNAL_SECRET).
    # 3.8: режим фиксируем явно (-mode node/master, + -also-node для master+node).
    API_UNIT_AFTER="network.target"
    [ "$NODE_INSTALL" = "1" ] && API_UNIT_AFTER="network.target vkturn-hy2.service"
    NODE_FLAGS=""
    [ "$NODE_INSTALL" = "1" ] && NODE_FLAGS="\\
  -hy2-port $HY2_PORT \\
  -port-start $PORT_START \\
  -port-end $PORT_END"
    ALSO_NODE_FLAG=""
    [ "$ROLE" = "master+node" ] && ALSO_NODE_FLAG=" \\
  -also-node"
    cat > /etc/systemd/system/vkturn-api.service << EOF
[Unit]
Description=VKTurn API (subscription keys)
After=$API_UNIT_AFTER

[Service]
Type=simple
EnvironmentFile=$INSTALL_DIR/api.env
UMask=0077
ExecStart=$INSTALL_DIR/api \\
  -db $INSTALL_DIR/api.db \\
  -dir $INSTALL_DIR \\
  -bind 0.0.0.0 \\
  -port $API_PORT \\
  -mode $API_MODE $ALSO_NODE_FLAG$NODE_FLAGS
Restart=always
RestartSec=3
StandardOutput=append:$LOG_DIR/api.log
StandardError=append:$LOG_DIR/api.log

[Install]
WantedBy=multi-user.target
EOF
fi

# ── Firewall ──────────────────────────────────────────────────────────────────
step "Настройка firewall"
# Реальный порт SSH (может быть не 22) — иначе ufw --force enable отрежет доступ.
SSH_PORT=$(sshd -T 2>/dev/null | awk '/^port /{print $2; exit}' || true)
if ! [[ "${SSH_PORT:-}" =~ ^[0-9]+$ ]]; then
    SSH_PORT=$(ss -tlnp 2>/dev/null | awk '/sshd/ {n=split($4,a,":"); print a[n]; exit}' || true)
fi
[[ "${SSH_PORT:-}" =~ ^[0-9]+$ ]] || SSH_PORT=22
info "Порт SSH: $SSH_PORT"

if ufw status 2>/dev/null | grep -qE 'Status: (active|inactive)'; then
    ufw allow "$SSH_PORT"/tcp comment "SSH"    >/dev/null 2>&1 || true
    if [ "$NODE_INSTALL" = "1" ]; then
        ufw allow $VKSERV_PORT/udp comment "VKTurn" >/dev/null 2>&1 || true
        # Диапазон личных портов ключей — правилом ufw (переживает ufw reload, в отличие от одиночных iptables -I)
        ufw allow $PORT_START:$PORT_END/udp comment "VKTurn keys" >/dev/null 2>&1 || true
    fi
    [ "$API_INSTALLED" = "1" ] && { ufw allow $API_PORT/tcp comment "VKTurn API" >/dev/null 2>&1 || true; }
    ufw --force enable >/dev/null 2>&1 || true
    [ "$NODE_INSTALL" = "1" ] && info "Порт $VKSERV_PORT/UDP открыт (ufw)"
    [ "$API_INSTALLED" = "1" ] && info "Порт $API_PORT/TCP (API) открыт (ufw)"
else
    if [ "$NODE_INSTALL" = "1" ]; then
        iptables -I INPUT -p udp --dport $VKSERV_PORT -j ACCEPT 2>/dev/null && \
            info "Порт $VKSERV_PORT/UDP открыт (iptables)" || \
            warn "Порт $VKSERV_PORT/UDP: открой вручную в панели хостинга"
        iptables -I INPUT -p udp --dport $PORT_START:$PORT_END -j ACCEPT 2>/dev/null && \
            info "Диапазон $PORT_START:$PORT_END/UDP открыт (iptables)" || \
            warn "Диапазон $PORT_START:$PORT_END/UDP: открой вручную в панели хостинга"
    fi
    if [ "$API_INSTALLED" = "1" ]; then
        iptables -I INPUT -p tcp --dport $API_PORT -j ACCEPT 2>/dev/null && \
            info "Порт $API_PORT/TCP (API) открыт (iptables)" || \
            warn "Порт $API_PORT/TCP: открой вручную в панели хостинга"
    fi
fi

# ── Запуск сервисов ───────────────────────────────────────────────────────────
step "Запуск сервисов"
systemctl daemon-reload
if [ "$NODE_INSTALL" = "1" ]; then
systemctl enable --now vkturn-hy2.service
sleep 2
systemctl enable --now vkturn-server.service
sleep 1

if systemctl is-active --quiet vkturn-hy2.service; then
    info "hysteria2: running ✓"
else
    warn "hysteria2 не запустился. Лог: journalctl -u vkturn-hy2 -n 20"
fi

if systemctl is-active --quiet vkturn-server.service; then
    info "vkserv: running ✓"
else
    warn "vkserv не запустился. Лог: journalctl -u vkturn-server -n 20"
fi
fi

TLS_PIN=""
API_HEALTHY=0
if [ "$API_INSTALLED" = "1" ]; then
    systemctl enable --now vkturn-api.service
    # Дожидаемся health: API слушает только HTTPS, при первом старте генерирует
    # сертификат в $INSTALL_DIR/tls (SAN = PUBLIC_URL, поэтому PUBLIC_URL должен быть задан выше).
    for _i in 1 2 3 4 5 6 7 8 9 10 11 12; do
        if curl -fsS --max-time 5 -k https://127.0.0.1:$API_PORT/health >/dev/null 2>&1; then
            API_HEALTHY=1; break
        fi
        sleep 1
    done
    if [ "$API_HEALTHY" = "1" ]; then
        info "vkturn-api: running ✓ (https://$SERVER_IP:$API_PORT)"
    else
        warn "vkturn-api не отвечает на https://127.0.0.1:$API_PORT/health. Лог: journalctl -u vkturn-api -n 20"
    fi

    # SPKI-пин API (SHA-256 от SubjectPublicKeyInfo, строчный hex, НЕ секрет).
    # Источник 1 — сам сертификат tls/api.crt, источник 2 (запасной) — строка лога API.
    if [ -f "$INSTALL_DIR/tls/api.crt" ]; then
        TLS_PIN=$(openssl x509 -in "$INSTALL_DIR/tls/api.crt" -pubkey -noout 2>/dev/null | \
                  openssl pkey -pubin -outform DER 2>/dev/null | sha256sum | awk '{print $1}' || true)
        # sha256 пустого ввода = openssl не смог прочитать сертификат
        [ "$TLS_PIN" = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" ] && TLS_PIN=""
    fi
    if [ -z "$TLS_PIN" ]; then
        TLS_PIN=$(grep -o 'TLS_PIN=[0-9a-f]\{64\}' "$LOG_DIR/api.log" 2>/dev/null | tail -n1 | cut -d= -f2 || true)
    fi
    if [ -n "$TLS_PIN" ]; then
        info "TLS-пин API получен (записан в config.txt)"
    else
        warn "Не удалось прочитать TLS-пин — проверь $LOG_DIR/api.log (строка TLS_PIN=...)"
    fi

    # Учёт трафика ведёт сам vkturn-api (читает users/<port>.stats от server).
    # Старый cron-трекер (iptables, считал только входящий трафик) убираем при переустановке.
    # Ничто здесь не должно ронять скрипт (set -e) — иначе приложение не получит vkturn://.
    if command -v crontab &>/dev/null && crontab -l 2>/dev/null | grep tracker.sh >/dev/null; then
        { crontab -l 2>/dev/null | { grep -v tracker.sh || true; }; } | crontab - || true
    fi
    rm -f "$INSTALL_DIR/tracker.sh"
fi

# ── Генерация vkturn:// (только нода) ─────────────────────────────────────────
step "Генерация конфига для приложения"
VKTURN_LINK=""
if [ "$NODE_INSTALL" = "1" ]; then
HY2_PROFILE="hysteria2://${HY2_PASS}@${SERVER_IP}:${HY2_PORT}?sni=${SERVER_IP}&insecure=1#${SERVER_NAME}"
JSON="{\"n\":\"${SERVER_NAME}\",\"peer\":\"${SERVER_IP}:${VKSERV_PORT}\",\"vk\":\"${VK_LINK}\",\"pwd\":\"${WRAP_PASS}\",\"profile\":\"${HY2_PROFILE}\"${TLS_PIN:+,\"pin\":\"${TLS_PIN}\"}}"
B64=$(echo -n "$JSON" | openssl base64 -A | tr '+/' '-_' | tr -d '=')
VKTURN_LINK="vkturn://v1/${B64}"
fi

# ── Сохраняем конфиг ──────────────────────────────────────────────────────────
cat > "$INSTALL_DIR/config.txt" << EOF
# VKTurn конфиг — $(date)
ROLE=$ROLE
SERVER_IP=$SERVER_IP
VKSERV_PORT=$VKSERV_PORT
HY2_PORT=$HY2_PORT
WRAP_PASS=$WRAP_PASS
HY2_PASS=$HY2_PASS
VK_LINK=$VK_LINK
ADMIN_TOKEN=$ADMIN_TOKEN
MASTER_TOKEN=$MASTER_TOKEN
INTERNAL_SECRET=$INTERNAL_SECRET
PORT_START=$PORT_START
PORT_END=$PORT_END
VKTURN_LINK=$VKTURN_LINK
${TLS_PIN:+TLS_PIN=$TLS_PIN}
EOF
chmod 600 "$INSTALL_DIR/config.txt"

# ── Вывод результата ──────────────────────────────────────────────────────────
echo ""
echo -e "${G}╔══════════════════════════════════════════════════════════╗${N}"
echo -e "${G}║              ✅  VKTurn успешно установлен               ║${N}"
echo -e "${G}╚══════════════════════════════════════════════════════════╝${N}"
echo ""
echo -e "${W}Роль:${N} $ROLE"

if [ "$NODE_INSTALL" = "1" ] && [ -n "$VKTURN_LINK" ]; then
echo -e "${W}Ссылка для импорта:${N}"
echo ""
echo "$VKTURN_LINK"
echo ""

if command -v qrencode &>/dev/null; then
    qrencode -t ANSIUTF8 -m 1 "$VKTURN_LINK"
    echo ""
fi
fi

# 3.7: регистрация этой ноды на мастере (JOIN_URL/JOIN + JOIN_TOKEN + JOIN_PIN).
# Нода уже установлена и запущена, TLS_PIN её API известен — регистрируем.
JOIN_STATUS=0
if [ "$NODE_INSTALL" = "1" ] && [ -n "$JOIN_URL" ]; then
    if [ -z "$JOIN_TOKEN" ]; then
        warn "JOIN_URL задан, но JOIN_TOKEN пуст — регистрация на мастере пропущена. Выдай join-токен на мастере и перезапусти: JOIN_URL=... JOIN_TOKEN=... JOIN_PIN=... bash install.sh (или FORCE_REINSTALL=1)"
    elif [ -z "$JOIN_PIN" ]; then
        warn "JOIN_URL задан, но JOIN_PIN пуст — регистрация НЕ выполнена. Пин мастера обязателен (правило «пин до токена»): получи TLS_PIN мастера и передай JOIN_PIN=<hex64>"
    elif [ -z "$TLS_PIN" ]; then
        warn "Не определён собственный TLS-пин ноды — регистрация на мастере пропущена (нечего отправлять в поле pin)"
    else
        step "Регистрация ноды на мастере"
        # hex64 → base64 для --pinnedpubkey (xxd из vim-common; fallback — printf+sed,
        # тот же приём, что для собственного пина API ниже по скрипту).
        if command -v xxd >/dev/null 2>&1; then
            JOIN_PIN_B64=$(echo "$JOIN_PIN" | xxd -r -p | base64 | tr -d '\n' || true)
        else
            JOIN_PIN_B64=$(printf "$(printf '%s' "$JOIN_PIN" | sed 's/../\\x&/g')" | base64 | tr -d '\n' || true)
        fi
        echo "$JOIN_PIN" | grep -qE '^[0-9a-fA-F]{64}$' || JOIN_PIN_B64=""
        if [ -z "$JOIN_PIN_B64" ]; then
            warn "JOIN_PIN не похож на hex64 SPKI-пин — регистрация НЕ выполнена"
        else
            # JOIN_URL допускается без схемы — по умолчанию HTTPS
            case "$JOIN_URL" in
                http://*|https://*) : ;;
                *) JOIN_URL="https://$JOIN_URL" ;;
            esac
            JOIN_URL="${JOIN_URL%/}"
            JOIN_HTTP=$(curl -sS --max-time 20 -k --pinnedpubkey "sha256//$JOIN_PIN_B64" \
                -w '\n%{http_code}' -X POST "$JOIN_URL/v1/master/join" \
                -H "Content-Type: application/json" \
                -d "{\"token\":\"$JOIN_TOKEN\",\"api\":\"$SERVER_IP:$API_PORT\",\"pin\":\"$TLS_PIN\",\"master_token\":\"$MASTER_TOKEN\",\"name\":\"$(hostname)\",\"version\":\"${VKSERV_VERSION%%-*}\",\"capacity\":$JOIN_CAPACITY}" 2>/tmp/vkturn-join.err) \
                && JOIN_HTTP_OK=1 || JOIN_HTTP_OK=0
            JOIN_BODY=$(echo "$JOIN_HTTP" | sed '$d')
            JOIN_CODE=$(echo "$JOIN_HTTP" | tail -n1)
            if [ "$JOIN_HTTP_OK" = "1" ] && [ "$JOIN_CODE" = "200" ] && grep -q '"registered"' <<<"$JOIN_BODY"; then
                JOIN_STATUS=1
                info "Нода зарегистрирована на мастере $JOIN_URL ✓"
                printf 'VKTURN_JOIN_STATUS=registered\n'
            elif [ "$JOIN_HTTP_OK" = "1" ] && [ "$JOIN_CODE" = "403" ]; then
                warn "Мастер отклонил join-токен (403: join token invalid or expired). Токен одноразовый и живёт 1 час — выдай новый на мастере: curl -k -X POST $JOIN_URL/v1/master/join-tokens -H 'X-Admin-Token: <ADMIN_TOKEN мастера>'"
            else
                JOIN_ERR=""
                [ -s /tmp/vkturn-join.err ] && JOIN_ERR=" (stderr: $(tail -n1 /tmp/vkturn-join.err))"
                warn "Не удалось зарегистрироваться на мастере (код: ${JOIN_CODE:-нет}). Ответ: ${JOIN_BODY:-пусто}${JOIN_ERR}"
            fi
        fi
    fi
fi

# Вывод без ANSI — для парсинга приложением
printf 'VKTURN_ADMIN_TOKEN=%s\n' "$ADMIN_TOKEN"
printf 'VKTURN_MASTER_TOKEN=%s\n' "$MASTER_TOKEN"
if [ -n "$TLS_PIN" ]; then printf 'VKTURN_ADMIN_PIN=%s\n' "$TLS_PIN"; fi
if [ "$ROLE" != "node" ]; then printf 'VKTURN_ROLE=%s\n' "$ROLE"; fi

if [ "$API_INSTALLED" = "1" ]; then
    echo -e "${W}Admin token:${N} $ADMIN_TOKEN"
    echo -e "${W}Master token:${N} $MASTER_TOKEN"
    if [ -n "$TLS_PIN" ]; then
        # --pinnedpubkey принимает base64 того же SPKI-хэша, что в TLS_PIN (hex). Только openssl.
        PIN_B64=""
        if [ -f "$INSTALL_DIR/tls/api.crt" ]; then
            PIN_B64=$(openssl x509 -in "$INSTALL_DIR/tls/api.crt" -pubkey -noout 2>/dev/null | \
                      openssl pkey -pubin -outform DER 2>/dev/null | \
                      openssl dgst -sha256 -binary 2>/dev/null | openssl base64 -A 2>/dev/null || true)
        fi
        if [ -z "$PIN_B64" ]; then
            # Запасной путь: hex → байты встроенным printf (TLS_PIN — строго [0-9a-f]{64})
            PIN_B64=$(printf "$(printf '%s' "$TLS_PIN" | sed 's/../\\x&/g')" | openssl base64 -A 2>/dev/null || true)
        fi
        PIN_FLAG="--pinnedpubkey sha256//${PIN_B64}"
    else
        PIN_FLAG=""
    fi
    echo -e "${W}Создать ключ:${N} (API — только HTTPS, соединение закрепляется пином)"
    echo "  curl $PIN_FLAG -X POST https://$SERVER_IP:$API_PORT/admin/keys/create \\"
    echo "    -H 'X-Admin-Token: $ADMIN_TOKEN' \\"
    echo "    -d '{\"expires_days\":30,\"bytes_limit\":10737418240,\"notes\":\"user1\"}'"
    if [ -n "$TLS_PIN" ] && [ -z "$PIN_B64" ]; then
        echo "  (base64-пин для curl: openssl x509 -in $INSTALL_DIR/tls/api.crt -pubkey -noout | openssl pkey -pubin -outform DER | openssl dgst -sha256 -binary | openssl base64 -A)"
    fi
fi

echo ""
echo -e "${W}Конфиг:${N} $INSTALL_DIR/config.txt"
if [ "$NODE_INSTALL" = "1" ]; then
    echo -e "${W}Логи:${N}  journalctl -u vkturn-hy2 -u vkturn-server -f"
else
    echo -e "${W}Логи:${N}  journalctl -u vkturn-api -f"
fi

# ── Подсказки мастера (3.7) ───────────────────────────────────────────────────
if [ "$IS_MASTER" = "1" ] && [ "$API_INSTALLED" = "1" ]; then
    echo ""
    echo -e "${W}Мастер запущен: https://$SERVER_IP:$API_PORT (режим: $ROLE)${N}"
    echo -e "${W}1. Выдать join-токен для новой ноды:${N}"
    echo "  curl -k -X POST https://$SERVER_IP:$API_PORT/v1/master/join-tokens \\"
    echo "    -H 'X-Admin-Token: $ADMIN_TOKEN'"
    echo "  → {\"token\":\"<hex>\",\"expires_at\":<unix,+1ч>} (одноразовый)"
    echo -e "${W}2. Зарегистрировать ноду (на самой ноде):${N}"
    echo "  JOIN_URL=https://$SERVER_IP:$API_PORT JOIN_TOKEN=<hex> JOIN_PIN=<TLS_PIN мастера> bash install.sh"
    echo "  (JOIN_PIN — строка TLS_PIN= из config.txt мастера; нода получает его от владельца вручную)"
    if [ "$NODE_INSTALL" = "0" ]; then
        echo -e "${Y}Режим master без -also-node: hysteria2 и vkserv не установлены — это чистый админ-сервер.${N}"
    fi
fi
echo ""

# ── Скрипт обновления VK ссылки ──────────────────────────────────────────────
cat > "$INSTALL_DIR/update-vk.sh" << 'UPDATEEOF'
#!/bin/bash
# Обновление VK-ссылки (F8): без `source config.txt` — значения читаются grep/cut,
# чтобы чужая строка в конфиге не исполнилась как код. Формат ссылки тот же, что в health.go.
set -u
INSTALL_DIR="${VKTURN_DIR:-/opt/vkturn}"
CONFIG="$INSTALL_DIR/config.txt"
[ -f "$CONFIG" ] || { echo "Нет $CONFIG"; exit 1; }

cfg() { grep -m1 "^$1=" "$CONFIG" | cut -d= -f2-; }

if [ $# -ge 1 ] && [ -n "$1" ]; then NEW_VK="$1"; else read -rp "Новая VK ссылка: " NEW_VK; fi
NEW_VK=$(echo "$NEW_VK" | tr -d '[:space:]')
echo "$NEW_VK" | grep -qE '^https://vk\.(com|ru)/call/join/[A-Za-z0-9_-]+$' || { echo "Неверная ссылка. Ожидается https://vk.com/call/join/XXXX"; exit 1; }

SERVER_IP=$(cfg SERVER_IP)
VKSERV_PORT=$(cfg VKSERV_PORT)
HY2_PORT=$(cfg HY2_PORT)
HY2_PASS=$(cfg HY2_PASS)
WRAP_PASS=$(cfg WRAP_PASS)
[ -n "$SERVER_IP" ] && [ -n "$VKSERV_PORT" ] && [ -n "$HY2_PASS" ] || { echo "config.txt неполный"; exit 1; }

cp -a "$CONFIG" "$CONFIG.bak" || { echo "Не удалось сделать бэкап config.txt"; exit 1; }
sed -i "s|^VK_LINK=.*|VK_LINK=$NEW_VK|" "$CONFIG"

HY2_PROFILE="hysteria2://${HY2_PASS}@${SERVER_IP}:${HY2_PORT}?sni=${SERVER_IP}&insecure=1#VKTurn"
JSON="{\"n\":\"VKTurn\",\"peer\":\"${SERVER_IP}:${VKSERV_PORT}\",\"vk\":\"${NEW_VK}\",\"pwd\":\"${WRAP_PASS}\",\"profile\":\"${HY2_PROFILE}\"}"
B64=$(echo -n "$JSON" | openssl base64 -A | tr '+/' '-_' | tr -d '=')
LINK="vkturn://v1/${B64}"
echo ""
echo "$LINK"
command -v qrencode &>/dev/null && qrencode -t ANSIUTF8 -m 1 "$LINK"
UPDATEEOF
chmod 600 "$INSTALL_DIR/update-vk.sh" && chmod +x "$INSTALL_DIR/update-vk.sh"
