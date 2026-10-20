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
VKSERV_VERSION="${VKSERV_VERSION:-v1.0.2}"
VKSERV_REPO="https://github.com/Maximusikk/vk-serv-core/releases/download/$VKSERV_VERSION"
HY2_REPO="https://github.com/apernet/hysteria/releases/latest/download"
INSTALL_DIR="/opt/vkturn"
LOG_DIR="/var/log/vkturn"
VKSERV_PORT=56000
HY2_PORT=10443
API_PORT=7000

# ── Проверка root ──────────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && error "Запускай от root: sudo bash install.sh"

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
apt-get install -y -qq curl wget openssl ufw qrencode 2>/dev/null || \
  apt-get install -y -qq curl wget openssl ufw 2>/dev/null
info "Зависимости установлены"

# ── Генерация паролей ─────────────────────────────────────────────────────────
step "Генерация конфигурации"
WRAP_PASS=$(openssl rand -hex 16)
HY2_PASS=$(openssl rand -hex 16)
SERVER_NAME="VKTurn-$(hostname | cut -c1-8)"

# Токены API — генерируем всегда
ADMIN_TOKEN=$(openssl rand -hex 24)
INTERNAL_SECRET=$(openssl rand -hex 24)
PORT_START=56001
PORT_END=57000

info "Wrap password: $WRAP_PASS"
info "Hy2 password:  $HY2_PASS"

# ── Ввод VK ссылки ────────────────────────────────────────────────────────────
step "VK звонок"
echo ""
echo -e "${Y}Создай звонок в VK:${N}"
echo "  1. Открой ВКонтакте → Звонки → Создать звонок → Конференция"
echo "  2. БЕЗ пароля"
echo "  3. Скопируй ссылку вида https://vk.com/call/join/ХХХХ"
echo ""
if [ -z "${VK_LINK:-}" ]; then
    read -rp "Вставь ссылку VK звонка: " VK_LINK
fi
echo "$VK_LINK" | grep -qE 'vk\.(com|ru)/call/join/' || error "Неверная ссылка. Ожидается https://vk.com/call/join/... или vk.ru/call/join/..."
info "VK ссылка принята"

# ── Остановка старых сервисов (при переустановке) ────────────────────────────
for _svc in vkturn-api vkturn-server vkturn-hy2; do
    systemctl stop "$_svc" 2>/dev/null || true
done
sleep 1

# ── Директории ────────────────────────────────────────────────────────────────
step "Создание директорий"
mkdir -p "$INSTALL_DIR" "$INSTALL_DIR/users" "$LOG_DIR"
chmod 755 "$INSTALL_DIR"

# ── Скачивание vkserv ─────────────────────────────────────────────────────────
step "Загрузка vkserv"
wget -q --show-progress -O "$INSTALL_DIR/server" "$VKSERV_REPO/server-linux-$ARCH_SUFFIX"
chmod +x "$INSTALL_DIR/server"
info "vkserv OK"

# ── Скачивание hysteria2 ──────────────────────────────────────────────────────
step "Загрузка hysteria2"
wget -q --show-progress -O "$INSTALL_DIR/hysteria2" "$HY2_REPO/hysteria-linux-$ARCH_SUFFIX"
chmod +x "$INSTALL_DIR/hysteria2"
info "hysteria2 OK"

# ── API сервер подписок ───────────────────────────────────────────────────────
step "Загрузка API сервера подписок"
API_URL="$VKSERV_REPO/vkturn-api-$ARCH_SUFFIX"
API_INSTALLED=0
if wget -q --spider "$API_URL" 2>/dev/null; then
    wget -q --show-progress -O "$INSTALL_DIR/api" "$API_URL"
    chmod +x "$INSTALL_DIR/api"
    API_INSTALLED=1
    info "vkturn-api OK"
else
    warn "vkturn-api не найден в releases — админка недоступна (токены всё равно сохранены)"
fi

# ── TLS сертификат ────────────────────────────────────────────────────────────
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

# ── Конфиг hysteria2 ──────────────────────────────────────────────────────────
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

# ── Systemd сервисы ───────────────────────────────────────────────────────────
step "Настройка systemd"

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

# API сервер (если скачался)
if [ "$API_INSTALLED" = "1" ]; then
    cat > /etc/systemd/system/vkturn-api.service << EOF
[Unit]
Description=VKTurn API (subscription keys)
After=network.target vkturn-hy2.service

[Service]
Type=simple
ExecStart=$INSTALL_DIR/api \\
  -db $INSTALL_DIR/api.db \\
  -dir $INSTALL_DIR \\
  -bind 0.0.0.0 \\
  -port $API_PORT \\
  -hy2-port $HY2_PORT \\
  -port-start $PORT_START \\
  -port-end $PORT_END \\
  -admin-token $ADMIN_TOKEN \\
  -internal-secret $INTERNAL_SECRET
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
if ufw status 2>/dev/null | grep -qE 'Status: (active|inactive)'; then
    ufw allow ssh         comment "SSH"    >/dev/null 2>&1 || true
    ufw allow $VKSERV_PORT/udp comment "VKTurn" >/dev/null 2>&1 || true
    [ "$API_INSTALLED" = "1" ] && { ufw allow $API_PORT/tcp comment "VKTurn API" >/dev/null 2>&1 || true; }
    ufw --force enable >/dev/null 2>&1 || true
    info "Порт $VKSERV_PORT/UDP открыт (ufw)"
    [ "$API_INSTALLED" = "1" ] && info "Порт $API_PORT/TCP (API) открыт (ufw)"
else
    iptables -I INPUT -p udp --dport $VKSERV_PORT -j ACCEPT 2>/dev/null && \
        info "Порт $VKSERV_PORT/UDP открыт (iptables)" || \
        warn "Порт $VKSERV_PORT/UDP: открой вручную в панели хостинга"
    if [ "$API_INSTALLED" = "1" ]; then
        iptables -I INPUT -p tcp --dport $API_PORT -j ACCEPT 2>/dev/null && \
            info "Порт $API_PORT/TCP (API) открыт (iptables)" || \
            warn "Порт $API_PORT/TCP: открой вручную в панели хостинга"
    fi
fi

# ── Запуск сервисов ───────────────────────────────────────────────────────────
step "Запуск сервисов"
systemctl daemon-reload
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

if [ "$API_INSTALLED" = "1" ]; then
    systemctl enable --now vkturn-api.service
    sleep 1
    if systemctl is-active --quiet vkturn-api.service; then
        info "vkturn-api: running ✓ (http://$SERVER_IP:$API_PORT)"
    else
        warn "vkturn-api не запустился. Лог: journalctl -u vkturn-api -n 20"
    fi

    # Учёт трафика ведёт сам vkturn-api (читает users/<port>.stats от server).
    # Старый cron-трекер (iptables, считал только входящий трафик) убираем при переустановке.
    # Ничто здесь не должно ронять скрипт (set -e) — иначе приложение не получит vkturn://.
    if command -v crontab &>/dev/null && crontab -l 2>/dev/null | grep tracker.sh >/dev/null; then
        { crontab -l 2>/dev/null | { grep -v tracker.sh || true; }; } | crontab - || true
    fi
    rm -f "$INSTALL_DIR/tracker.sh"
fi

# ── Генерация vkturn:// ───────────────────────────────────────────────────────
step "Генерация конфига для приложения"
HY2_PROFILE="hysteria2://${HY2_PASS}@${SERVER_IP}:${HY2_PORT}?sni=${SERVER_IP}&insecure=1#${SERVER_NAME}"
JSON="{\"n\":\"${SERVER_NAME}\",\"peer\":\"${SERVER_IP}:${VKSERV_PORT}\",\"vk\":\"${VK_LINK}\",\"pwd\":\"${WRAP_PASS}\",\"profile\":\"${HY2_PROFILE}\"}"
B64=$(echo -n "$JSON" | openssl base64 -A | tr '+/' '-_' | tr -d '=')
VKTURN_LINK="vkturn://v1/${B64}"

# ── Сохраняем конфиг ──────────────────────────────────────────────────────────
cat > "$INSTALL_DIR/config.txt" << EOF
# VKTurn конфиг — $(date)
SERVER_IP=$SERVER_IP
VKSERV_PORT=$VKSERV_PORT
HY2_PORT=$HY2_PORT
WRAP_PASS=$WRAP_PASS
HY2_PASS=$HY2_PASS
VK_LINK=$VK_LINK
ADMIN_TOKEN=$ADMIN_TOKEN
INTERNAL_SECRET=$INTERNAL_SECRET
PORT_START=$PORT_START
PORT_END=$PORT_END
VKTURN_LINK=$VKTURN_LINK
EOF
chmod 600 "$INSTALL_DIR/config.txt"

# ── Вывод результата ──────────────────────────────────────────────────────────
echo ""
echo -e "${G}╔══════════════════════════════════════════════════════════╗${N}"
echo -e "${G}║              ✅  VKTurn успешно установлен               ║${N}"
echo -e "${G}╚══════════════════════════════════════════════════════════╝${N}"
echo ""
echo -e "${W}Ссылка для импорта:${N}"
echo ""
echo "$VKTURN_LINK"
echo ""

if command -v qrencode &>/dev/null; then
    qrencode -t ANSIUTF8 -m 1 "$VKTURN_LINK"
    echo ""
fi

# Вывод без ANSI — для парсинга приложением
printf 'VKTURN_ADMIN_TOKEN=%s\n' "$ADMIN_TOKEN"

if [ "$API_INSTALLED" = "1" ]; then
    echo -e "${W}Admin token:${N} $ADMIN_TOKEN"
    echo -e "${W}Создать ключ:${N}"
    echo "  curl -X POST http://$SERVER_IP:$API_PORT/admin/keys/create \\"
    echo "    -H 'X-Admin-Token: $ADMIN_TOKEN' \\"
    echo "    -d '{\"expires_days\":30,\"bytes_limit\":10737418240,\"notes\":\"user1\"}'"
fi

echo ""
echo -e "${W}Конфиг:${N} $INSTALL_DIR/config.txt"
echo -e "${W}Логи:${N}  journalctl -u vkturn-hy2 -u vkturn-server -f"
echo ""

# ── Скрипт обновления VK ссылки ──────────────────────────────────────────────
cat > "$INSTALL_DIR/update-vk.sh" << 'UPDATEEOF'
#!/bin/bash
INSTALL_DIR="/opt/vkturn"
source "$INSTALL_DIR/config.txt" 2>/dev/null || true
read -rp "Новая VK ссылка: " NEW_VK
echo "$NEW_VK" | grep -qE 'vk\.(com|ru)/call/join/' || { echo "Неверная ссылка"; exit 1; }
sed -i "s|VK_LINK=.*|VK_LINK=$NEW_VK|" "$INSTALL_DIR/config.txt"
source "$INSTALL_DIR/config.txt"
HY2_PROFILE="hysteria2://${HY2_PASS}@${SERVER_IP}:${HY2_PORT}?sni=${SERVER_IP}&insecure=1#VKTurn"
JSON="{\"n\":\"VKTurn\",\"peer\":\"${SERVER_IP}:${VKSERV_PORT}\",\"vk\":\"${NEW_VK}\",\"pwd\":\"${WRAP_PASS}\",\"profile\":\"${HY2_PROFILE}\"}"
B64=$(echo -n "$JSON" | openssl base64 -A | tr '+/' '-_' | tr -d '=')
LINK="vkturn://v1/${B64}"
echo ""
echo "$LINK"
command -v qrencode &>/dev/null && qrencode -t ANSIUTF8 -m 1 "$LINK"
UPDATEEOF
chmod +x "$INSTALL_DIR/update-vk.sh"
