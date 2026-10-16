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
VKSERV_REPO="https://github.com/Maximusikk/vk-serv-core/releases/latest/download"
HY2_REPO="https://github.com/apernet/hysteria/releases/latest/download"
INSTALL_DIR="/opt/vkturn"
LOG_DIR="/var/log/vkturn"
VKSERV_PORT=56000
HY2_PORT=10443

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

# Публичный IP
# Приоритет: env-переменная (IP передан из приложения) → автоопределение
if [ -z "${SERVER_IP:-}" ]; then
    SERVER_IP=$(curl -s4 https://api.ipify.org 2>/dev/null || curl -s4 https://ifconfig.me 2>/dev/null || "")
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

# Общий пароль для wrap (vkserv ↔ клиент)
WRAP_PASS=$(openssl rand -hex 16)
# Пароль для hysteria2 (телефон не знает, только через wrap-туннель)
HY2_PASS=$(openssl rand -hex 16)
# Имя сервера
SERVER_NAME="VKTurn-$(hostname | cut -c1-8)"

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
# Если передана через env (автонастройка из приложения) — пропускаем интерактивный ввод
if [ -z "${VK_LINK:-}" ]; then
    read -rp "Вставь ссылку VK звонка: " VK_LINK
fi
echo "$VK_LINK" | grep -qE 'vk\.(com|ru)/call/join/' || error "Неверная ссылка. Ожидается https://vk.com/call/join/... или vk.ru/call/join/..."
VK_HASH=$(echo "$VK_LINK" | grep -oP 'join/\K[^/?]+')
info "VK хеш: $VK_HASH"

# ── Директории ────────────────────────────────────────────────────────────────
step "Создание директорий"
mkdir -p "$INSTALL_DIR" "$LOG_DIR"
chmod 755 "$INSTALL_DIR"

# ── Скачивание vkserv ─────────────────────────────────────────────────────────
step "Загрузка vkserv"
VKSERV_URL="$VKSERV_REPO/server-linux-$ARCH_SUFFIX"
info "Скачиваю: $VKSERV_URL"
wget -q --show-progress -O "$INSTALL_DIR/server" "$VKSERV_URL"
chmod +x "$INSTALL_DIR/server"
info "vkserv: $("$INSTALL_DIR/server" --help 2>&1 | head -1 || echo "OK")"

# ── Скачивание hysteria2 ──────────────────────────────────────────────────────
step "Загрузка hysteria2"
HY2_URL="$HY2_REPO/hysteria-linux-$ARCH_SUFFIX"
info "Скачиваю: $HY2_URL"
wget -q --show-progress -O "$INSTALL_DIR/hysteria2" "$HY2_URL"
chmod +x "$INSTALL_DIR/hysteria2"
info "hysteria2: $("$INSTALL_DIR/hysteria2" version 2>/dev/null | head -1 || echo "OK")"

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
info "Сертификат создан (10 лет, самоподписанный)"

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
info "hysteria2 конфиг: $INSTALL_DIR/hy2.yaml"

# ── Systemd: hysteria2 ────────────────────────────────────────────────────────
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

# ── Systemd: vkserv ───────────────────────────────────────────────────────────
step "Конфигурация vkserv"
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

# ── Firewall ──────────────────────────────────────────────────────────────────
step "Настройка firewall"
# ufw не работает в LXC контейнерах — пробуем, при неудаче фаллбек через iptables
if ufw status 2>/dev/null | grep -qE 'Status: (active|inactive)'; then
    ufw allow ssh comment "SSH"                  >/dev/null 2>&1 || true
    ufw allow $VKSERV_PORT/udp comment "VKTurn"  >/dev/null 2>&1 || true
    ufw --force enable >/dev/null 2>&1 || true
    info "Порт $VKSERV_PORT/UDP открыт (ufw)"
else
    iptables -I INPUT -p udp --dport $VKSERV_PORT -j ACCEPT 2>/dev/null && \
        info "Порт $VKSERV_PORT/UDP открыт (iptables)" || \
        warn "Порт $VKSERV_PORT/UDP: открой вручную в панели хостинга"
fi

# ── Запуск сервисов ───────────────────────────────────────────────────────────
step "Запуск сервисов"
systemctl daemon-reload
systemctl enable --now vkturn-hy2.service
sleep 2
systemctl enable --now vkturn-server.service
sleep 2

# Проверяем что запустились
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

# ── C1: API сервер подписок ─────────────────────────────────────────────────
step "Загрузка API сервера подписок"
API_URL="$VKSERV_REPO/vkturn-api-$ARCH_SUFFIX"
if wget -q --spider "$API_URL" 2>/dev/null; then
    wget -q --show-progress -O "$INSTALL_DIR/api" "$API_URL"
    chmod +x "$INSTALL_DIR/api"
    mkdir -p "$INSTALL_DIR/users"

    # Генерируем токены
    ADMIN_TOKEN=$(openssl rand -hex 24)
    INTERNAL_SECRET=$(openssl rand -hex 24)
    PORT_START=56001
    PORT_END=57000
else
    # API бинарник не найден — всё равно генерируем токены для будущего использования
    warn "vkturn-api не найден в releases — генерирую токены для последующей установки"
    ADMIN_TOKEN=$(openssl rand -hex 24)
    INTERNAL_SECRET=$(openssl rand -hex 24)
    PORT_START=56001
    PORT_END=57000
fi
if false; then  # dummy закрытие предыдущего if

    # Systemd: vkturn-api.service
    cat > /etc/systemd/system/vkturn-api.service << APIEOF
[Unit]
Description=VKTurn API (subscription keys)
After=network.target vkturn-hy2.service

[Service]
Type=simple
ExecStart=$INSTALL_DIR/api \\
  -db $INSTALL_DIR/api.db \\
  -dir $INSTALL_DIR \\
  -port 7000 \\
  -hy2-port $HY2_PORT \\
  -port-start $PORT_START \\
  -port-end $PORT_END
Restart=always
RestartSec=3
StandardOutput=append:$LOG_DIR/api.log
StandardError=append:$LOG_DIR/api.log

[Install]
WantedBy=multi-user.target
APIEOF

    # Systemd шаблон для юзерских vkserv инстансов
    cat > /etc/systemd/system/vkserv@.service << TMPLEOF
[Unit]
Description=VKTurn user relay port %i
After=network.target vkturn-hy2.service

[Service]
Type=simple
EnvironmentFile=$INSTALL_DIR/users/%i.conf
ExecStart=$INSTALL_DIR/server \\
  -listen 0.0.0.0:%i \\
  -connect 127.0.0.1:$HY2_PORT \\
  -wrap \\
  -password \${WRAP_PASS}
Restart=on-failure
RestartSec=5
StandardOutput=append:$LOG_DIR/user-%i.log
StandardError=append:$LOG_DIR/user-%i.log

[Install]
WantedBy=multi-user.target
TMPLEOF

    # Устанавливаем tracker.sh
    cp "$(dirname "$0")/traffic_tracker.sh" "$INSTALL_DIR/tracker.sh" 2>/dev/null || \
        wget -q -O "$INSTALL_DIR/tracker.sh" \
        "https://raw.githubusercontent.com/Maximusikk/vk-serv-core/main/traffic_tracker.sh"
    chmod +x "$INSTALL_DIR/tracker.sh"

    # Cron: трекер каждые 30 секунд
    (crontab -l 2>/dev/null | grep -v tracker.sh; \
     echo "* * * * * $INSTALL_DIR/tracker.sh"; \
     echo "* * * * * sleep 30; $INSTALL_DIR/tracker.sh") | crontab -

    # Запускаем API
    systemctl daemon-reload
    systemctl enable --now vkturn-api.service
    sleep 1
    if systemctl is-active --quiet vkturn-api.service; then
        info "vkturn-api: running ✓ (порт 7000, только localhost)"
    else
        warn "vkturn-api не запустился. Лог: journalctl -u vkturn-api -n 20"
    fi
fi

# ── Генерация vkturn:// ссылки ────────────────────────────────────────────────
step "Генерация конфига для приложения"

HY2_PROFILE="hysteria2://${HY2_PASS}@${SERVER_IP}:${HY2_PORT}?sni=${SERVER_IP}&insecure=1#${SERVER_NAME}"

# JSON → base64url (без Python зависимости)
JSON="{\"n\":\"${SERVER_NAME}\",\"peer\":\"${SERVER_IP}:${VKSERV_PORT}\",\"vk\":\"${VK_LINK}\",\"pwd\":\"${WRAP_PASS}\",\"profile\":\"${HY2_PROFILE}\"}"
B64=$(echo -n "$JSON" | openssl base64 -A | tr '+/' '-_' | tr -d '=')
VKTURN_LINK="vkturn://v1/${B64}"

# ── Сохраняем конфиг ──────────────────────────────────────────────────────────
cat > "$INSTALL_DIR/config.txt" << EOF
# VKTurn — конфиг сервера
# Создан: $(date)

SERVER_IP=$SERVER_IP
VKSERV_PORT=$VKSERV_PORT
HY2_PORT=$HY2_PORT
WRAP_PASS=$WRAP_PASS
HY2_PASS=$HY2_PASS
VK_LINK=$VK_LINK

# API сервер подписок (v2)
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
echo -e "${W}Ссылка для импорта в приложение:${N}"
echo ""
echo "$VKTURN_LINK"
echo ""

# QR в терминале (если qrencode доступен)
if command -v qrencode &>/dev/null; then
  echo -e "${W}QR-код:${N}"
  qrencode -t ANSIUTF8 -m 1 "$VKTURN_LINK"
  echo ""
fi

echo -e "${W}Логи:${N}"
echo "  journalctl -u vkturn-hy2 -f"
echo "  journalctl -u vkturn-server -f"
echo ""
echo -e "${W}Конфиг сохранён:${N} $INSTALL_DIR/config.txt"
echo ""

# Админ токен для API — plain вывод для парсинга приложением (без ANSI!)
if [ -n "${ADMIN_TOKEN:-}" ]; then
    printf 'VKTURN_ADMIN_TOKEN=%s\n' "$ADMIN_TOKEN"
    echo -e "${W}API сервер (v2 подписки):${N} http://127.0.0.1:7000"
    echo -e "${W}Admin token:${N} $ADMIN_TOKEN"
    echo -e "${W}Диапазон портов:${N} $PORT_START — $PORT_END"
    echo ""
    echo -e "${Y}Добавить ключ:${N}"
    echo "  curl -s -X POST http://localhost:7000/admin/keys/create \\"
    echo "    -H 'X-Admin-Token: $ADMIN_TOKEN' \\"
    echo "    -d '{\"expires_days\": 30, \"bytes_limit\": 10737418240, \"notes\": \"user1\"}'"
    echo ""
fi

echo -e "${Y}Важно: VK звонок надо обновлять когда истекает ссылка.${N}"
echo -e "${Y}Новая ссылка → запусти: bash $INSTALL_DIR/update-vk.sh${N}"
echo ""

# ── Скрипт обновления VK ссылки ───────────────────────────────────────────────
cat > "$INSTALL_DIR/update-vk.sh" << 'UPDATEEOF'
#!/bin/bash
INSTALL_DIR="/opt/vkturn"
source "$INSTALL_DIR/config.txt" 2>/dev/null || true

read -rp "Новая ссылка VK звонка: " NEW_VK
[[ "$NEW_VK" != *"vk.com/call/join/"* ]] && echo "Неверная ссылка" && exit 1

# Обновляем конфиг
sed -i "s|VK_LINK=.*|VK_LINK=$NEW_VK|" "$INSTALL_DIR/config.txt"

# Перегенерируем vkturn:// ссылку
source "$INSTALL_DIR/config.txt"
HY2_PROFILE="hysteria2://${HY2_PASS}@${SERVER_IP}:${HY2_PORT}?sni=${SERVER_IP}&insecure=1#VKTurn"
JSON="{\"n\":\"VKTurn\",\"peer\":\"${SERVER_IP}:${VKSERV_PORT}\",\"vk\":\"${NEW_VK}\",\"pwd\":\"${WRAP_PASS}\",\"profile\":\"${HY2_PROFILE}\"}"
B64=$(echo -n "$JSON" | openssl base64 -A | tr '+/' '-_' | tr -d '=')
LINK="vkturn://v1/${B64}"

echo ""
echo "Новый конфиг:"
echo "$LINK"
echo ""
command -v qrencode &>/dev/null && qrencode -t ANSIUTF8 -m 1 "$LINK"
UPDATEEOF
chmod +x "$INSTALL_DIR/update-vk.sh"
