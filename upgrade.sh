#!/bin/bash
# VKTurn — обновление уже установленного сервера (без переустановки).
# Ключи, база, пароли и VK-ссылка сохраняются.
#
# Использование:
#   curl -fsSL https://raw.githubusercontent.com/Maximusikk/vk-serv-core/main/upgrade.sh | sudo bash
#   или: sudo bash upgrade.sh
#   Другая версия: VKSERV_VERSION=v1.2.0-server-binary bash upgrade.sh

set -euo pipefail

R='\033[0;31m' G='\033[0;32m' Y='\033[1;33m' W='\033[1m' N='\033[0m'
info()  { echo -e "${G}[+]${N} $*"; }
warn()  { echo -e "${Y}[!]${N} $*"; }
error() { echo -e "${R}[✗]${N} $*"; exit 1; }
step()  { echo -e "\n${W}━━━ $* ━━━${N}"; }

VKSERV_VERSION="${VKSERV_VERSION:-v1.2.0-server-binary}"
VKSERV_REPO="https://github.com/Maximusikk/vk-serv-core/releases/download/$VKSERV_VERSION"
INSTALL_DIR="/opt/vkturn"
LOG_DIR="/var/log/vkturn"
API_PORT=7000
API_UNIT="/etc/systemd/system/vkturn-api.service"

# ── Проверки ──────────────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && error "Запускай от root: sudo bash upgrade.sh"
[ -x "$INSTALL_DIR/server" ] || error "VKTurn не установлен ($INSTALL_DIR/server нет) — используй install.sh"

case "$(uname -m)" in
  x86_64)  ARCH="amd64" ;;
  aarch64) ARCH="arm64" ;;
  *) error "Неподдерживаемая архитектура: $(uname -m)" ;;
esac

HAS_API=0
[ -f "$API_UNIT" ] && HAS_API=1

# ── Загрузка ──────────────────────────────────────────────────────────────────
step "Загрузка $VKSERV_VERSION ($ARCH)"
TMP=$(mktemp -d "$INSTALL_DIR/.upgrade.XXXXXX")
trap 'rm -rf "$TMP"' EXIT

# F5: обязательная проверка по SHA256SUMS из релиза. Обхода нет: если SHA256SUMS
# не скачался или в нём нет записи для ассета — это ошибка обновления (fail-closed).
verify_sha256() { # FILE ASSET
    local file="$1" asset="$2" want got
    if ! wget -q -O "$TMP/SHA256SUMS" "$VKSERV_REPO/SHA256SUMS" 2>/dev/null; then
        error "$asset: не удалось скачать SHA256SUMS из релиза $VKSERV_VERSION — проверка целостности обязательна. Обновление прервано; если релиз опубликован без SHA256SUMS, сообщите об этом."
    fi
    want=$(awk -v f="$asset" '{sub(/^*/,"",$2)} $2==f{print $1}' "$TMP/SHA256SUMS")
    if [ -z "$want" ]; then
        error "$asset: нет записи в SHA256SUMS релиза — проверка целостности обязательна"
    fi
    got=$(sha256sum "$file" | awk '{print $1}')
    if [ "$got" != "$want" ]; then
        error "$asset: не совпал SHA-256 (ожидалось $want, получено $got) — файл релиза повреждён?"
    fi
    info "$asset: SHA-256 сверён"
}

wget -q -O "$TMP/server" "$VKSERV_REPO/server-linux-$ARCH" || error "Не скачался server-linux-$ARCH"
verify_sha256 "$TMP/server" "server-linux-$ARCH"
chmod +x "$TMP/server"
# Новый server обязан уметь -stats-file, иначе юниты пользователей не запустятся
HELP=$("$TMP/server" -h 2>&1 || true)
grep stats-file <<<"$HELP" >/dev/null || error "Скачанный server без -stats-file — в релизе $VKSERV_VERSION старая сборка"
info "server OK"

if [ "$HAS_API" = "1" ]; then
    wget -q -O "$TMP/api" "$VKSERV_REPO/vkturn-api-$ARCH" || error "Не скачался vkturn-api-$ARCH"
    verify_sha256 "$TMP/api" "vkturn-api-$ARCH"
    chmod +x "$TMP/api"
    HELP=$("$TMP/api" -h 2>&1 || true)
    grep -- "-bind" <<<"$HELP" >/dev/null || error "Скачанный vkturn-api без -bind — в релизе $VKSERV_VERSION старая сборка"
    # TLS обязателен (контракт): API слушает только HTTPS, нужен флаг -tls-dir
    grep -- "-tls-dir" <<<"$HELP" >/dev/null || error "Скачанный vkturn-api без -tls-dir — в релизе $VKSERV_VERSION старая сборка без TLS"
    info "vkturn-api OK (TLS)"
fi

# ── Бэкап базы перед заменой (F11) ───────────────────────────────────────────
# Новая версия API может мигрировать схему api.db — откат бинарников базу не вернёт.
# sqlite3 .backup даёт согласованный снимок даже при работающем API (WAL).
DB_FILE="$INSTALL_DIR/api.db"
if [ "$HAS_API" = "1" ] && [ -f "$DB_FILE" ] && [ -z "${SKIP_DB_BACKUP:-}" ]; then
    step "Бэкап базы"
    DB_BACKUP_DIR="$INSTALL_DIR/backup-upgrade"
    DB_BACKUP="$DB_BACKUP_DIR/api.db.$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$DB_BACKUP_DIR"
    chmod 700 "$DB_BACKUP_DIR"
    if command -v sqlite3 &>/dev/null; then
        sqlite3 "$DB_FILE" ".backup '$DB_BACKUP'" || error "Не удалось сделать бэкап api.db (sqlite3 .backup). Обновление остановлено; пропустить: SKIP_DB_BACKUP=1"
    else
        # sqlite3 нет на старых установках: копируем базу вместе с WAL/SHM, чтобы снимок был целым
        warn "sqlite3 не найден — копирую файл базы целиком (api.db, -wal, -shm)"
        cp -f "$DB_FILE" "$DB_BACKUP" || error "Не удалось скопировать api.db. Обновление остановлено; пропустить: SKIP_DB_BACKUP=1"
        [ -f "$DB_FILE-wal" ] && cp -f "$DB_FILE-wal" "$DB_BACKUP-wal"
        [ -f "$DB_FILE-shm" ] && cp -f "$DB_FILE-shm" "$DB_BACKUP-shm"
    fi
    chmod 600 "$DB_BACKUP"* 2>/dev/null || true
    [ -s "$DB_BACKUP" ] || error "Бэкап api.db пустой — обновление остановлено"
    # хранить 5 последних, чтобы не съесть диск
    ls -1t "$DB_BACKUP_DIR"/api.db.* 2>/dev/null | grep -Ev -- '-(wal|shm)$' | tail -n +6 | while read -r _old; do
        rm -f "$_old" "$_old-wal" "$_old-shm"
    done || true
    info "База сохранена: $DB_BACKUP"
    info "Восстановить: systemctl stop vkturn-api && cp $DB_BACKUP $DB_FILE && systemctl start vkturn-api"
fi

# ── Замена бинарников (с резервной копией) ───────────────────────────────────
step "Установка"
cp -f "$INSTALL_DIR/server" "$INSTALL_DIR/server.bak"
mv -f "$TMP/server" "$INSTALL_DIR/server"   # mv — атомарно, работает и с запущенным процессом
if [ "$HAS_API" = "1" ]; then
    if [ -f "$INSTALL_DIR/api" ]; then cp -f "$INSTALL_DIR/api" "$INSTALL_DIR/api.bak"; fi
    mv -f "$TMP/api" "$INSTALL_DIR/api"
fi
info "Бинарники заменены (старые: *.bak)"

# ── Старый cron-трекер больше не нужен (учёт ведёт API) ──────────────────────
if command -v crontab &>/dev/null && crontab -l 2>/dev/null | grep tracker.sh >/dev/null; then
    { crontab -l 2>/dev/null | { grep -v tracker.sh || true; }; } | crontab - || true
    info "Старый cron-трекер трафика удалён"
fi
rm -f "$INSTALL_DIR/tracker.sh"

# ── API: слушать снаружи (для старых установок, где был только 127.0.0.1) ────
# 0.12: права на секреты для существующих установок
chmod 600 "$INSTALL_DIR/hy2.yaml" 2>/dev/null || true
[ -f "$INSTALL_DIR/api.db" ] && chmod 600 "$INSTALL_DIR/api.db"
if [ "$HAS_API" = "1" ]; then
    if ! grep -q "^UMask=" "$API_UNIT"; then
        sed -i "/^\[Service\]$/a UMask=0077" "$API_UNIT"
        info "UMask=0077 добавлен в $API_UNIT (0.12)"
    fi
fi
if [ "$HAS_API" = "1" ]; then
    if ! grep -- "-bind" "$API_UNIT" >/dev/null; then
        sed -i "s|-port $API_PORT|-bind 0.0.0.0 -port $API_PORT|" "$API_UNIT"
        info "vkturn-api теперь слушает 0.0.0.0:$API_PORT"
    fi

    # F4: миграция старых юнитов — токены из ExecStart в /opt/vkturn/api.env (600),
    # чтобы не светились в systemctl show / ps.
    if grep -E -- "-admin-token [^$]" "$API_UNIT" | grep -qv '\${'; then
        ADMIN_TOKEN_T=$(sed -n 's/.*-admin-token \([^ \\]*\).*/\1/p' "$API_UNIT" | head -1)
        INTERNAL_SECRET_T=$(sed -n 's/.*-internal-secret \([^ \\]*\).*/\1/p' "$API_UNIT" | head -1)
        if [ -n "$ADMIN_TOKEN_T" ] && [ -n "$INTERNAL_SECRET_T" ]; then
            umask 077
            cat > "$INSTALL_DIR/api.env" << EOF
ADMIN_TOKEN=$ADMIN_TOKEN_T
INTERNAL_SECRET=$INTERNAL_SECRET_T
EOF
            chmod 600 "$INSTALL_DIR/api.env"
            umask 022
            # 0.11: флаги удаляем совсем (systemd разворачивает ${VAR} до exec,
            # токен всё равно виден в ps). Удаление с учётом продолжений ExecStart «\»:
            # если после удаления флагов последняя строка ExecStart кончается «\» — срезаем.
            TMP_UNIT=$(mktemp)
            awk '
                /^ExecStart=/ && !blk { blk=1; n=0 }
                blk {
                    if ($0 ~ /-admin-token / || $0 ~ /-internal-secret /) next
                    buf[++n]=$0
                    if ($0 !~ /\\$/) {
                        sub(/\\$/, "", buf[n])
                        for (i=1;i<=n;i++) print buf[i]
                        n=0; blk=0
                    }
                    next
                }
                { print }
            ' "$API_UNIT" > "$TMP_UNIT" && mv -f "$TMP_UNIT" "$API_UNIT"
            if ! grep -q "EnvironmentFile=" "$API_UNIT"; then
                sed -i "/^\[Service\]$/a EnvironmentFile=$INSTALL_DIR/api.env" "$API_UNIT"
            fi
            info "Токены перенесены из юнита в $INSTALL_DIR/api.env (600)"
        else
            warn "Не удалось извлечь токены из юнита — проверь $API_UNIT вручную"
        fi
    fi
    # 0.11: у юнитов, мигрированных ранее в форму ${ADMIN_TOKEN}, токены всё ещё
    # видны в ps (systemd разворачивает переменные до exec). Если api.env полный —
    # вычищаем остаточные флаги совсем.
    if grep -q -- "-admin-token" "$API_UNIT" && [ -f "$INSTALL_DIR/api.env" ] \
       && grep -q '^ADMIN_TOKEN=' "$INSTALL_DIR/api.env" && grep -q '^INTERNAL_SECRET=' "$INSTALL_DIR/api.env"; then
        TMP_UNIT=$(mktemp)
        awk '
            /^ExecStart=/ && !blk { blk=1; n=0 }
            blk {
                if ($0 ~ /-admin-token / || $0 ~ /-internal-secret /) next
                buf[++n]=$0
                if ($0 !~ /\\$/) {
                    sub(/\\$/, "", buf[n])
                    for (i=1;i<=n;i++) print buf[i]
                    n=0; blk=0
                }
                next
            }
            { print }
        ' "$API_UNIT" > "$TMP_UNIT" && mv -f "$TMP_UNIT" "$API_UNIT"
        info "Остаточные -admin-token/-internal-secret удалены из юнита (0.11)"
    fi
    # G9: PUBLIC_URL (host:port без схемы) — иначе поле link в ответе create будет 127.0.0.1:7000.
    # Не трогаем, если уже задан в api.env или флагом -public-url в юните.
    if [ -f "$INSTALL_DIR/api.env" ]; then
        if ! grep -q '^PUBLIC_URL=' "$INSTALL_DIR/api.env" && ! grep -q -- '-public-url' "$API_UNIT"; then
            PUB_IP=$(grep '^SERVER_IP=' "$INSTALL_DIR/config.txt" 2>/dev/null | head -1 | cut -d= -f2 || true)
            if [ -n "$PUB_IP" ]; then
                echo "PUBLIC_URL=$PUB_IP:$API_PORT" >> "$INSTALL_DIR/api.env"
                info "PUBLIC_URL=$PUB_IP:$API_PORT добавлен в api.env"
            else
                warn "SERVER_IP не найден в config.txt — добавь PUBLIC_URL=<IP>:$API_PORT в $INSTALL_DIR/api.env вручную"
            fi
        fi
    else
        warn "Нет $INSTALL_DIR/api.env — PUBLIC_URL не задан, ссылки в ответе create будут с 127.0.0.1"
    fi
    if ufw status 2>/dev/null | grep "Status: active" >/dev/null; then
        ufw allow $API_PORT/tcp comment "VKTurn API" >/dev/null 2>&1 || true
    elif ! iptables -C INPUT -p tcp --dport $API_PORT -j ACCEPT 2>/dev/null; then
        iptables -I INPUT -p tcp --dport $API_PORT -j ACCEPT 2>/dev/null || true
    fi
fi

# ── Перезапуск ────────────────────────────────────────────────────────────────
step "Перезапуск сервисов"
systemctl daemon-reload
systemctl restart vkturn-server || true   # результат проверяется ниже, при ошибке — откат
# API при старте сам обновит шаблон vkserv@ (учёт трафика) и перезапустит порты пользователей
if [ "$HAS_API" = "1" ]; then systemctl restart vkturn-api || true; fi
sleep 4

rollback() {
    warn "$1 — откатываю на предыдущую версию"
    mv -f "$INSTALL_DIR/server.bak" "$INSTALL_DIR/server"
    if [ -f "$INSTALL_DIR/api.bak" ]; then mv -f "$INSTALL_DIR/api.bak" "$INSTALL_DIR/api"; fi
    systemctl restart vkturn-server || true
    if [ "$HAS_API" = "1" ]; then systemctl restart vkturn-api || true; fi
    error "Обновление отменено. Логи: journalctl -u vkturn-server -u vkturn-api -n 30"
}

systemctl is-active --quiet vkturn-server || rollback "vkturn-server не запустился"
info "vkturn-server: running ✓"

if [ "$HAS_API" = "1" ]; then
    systemctl is-active --quiet vkturn-api || rollback "vkturn-api не запустился"
    curl -fsS --max-time 5 -k "https://127.0.0.1:$API_PORT/health" >/dev/null || rollback "vkturn-api не отвечает на https://127.0.0.1:$API_PORT/health"
    info "vkturn-api: running ✓ (https://127.0.0.1:$API_PORT)"

    # TLS-пин (SHA-256 SPKI, hex64, НЕ секрет): источник 1 — сертификат tls/api.crt,
    # источник 2 (запасной) — строка лога API (в логе может быть пин старого сертификата).
    TLS_PIN=""
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
        if grep -q '^TLS_PIN=' "$INSTALL_DIR/config.txt" 2>/dev/null; then
            sed -i "s|^TLS_PIN=.*|TLS_PIN=$TLS_PIN|" "$INSTALL_DIR/config.txt"
        else
            echo "TLS_PIN=$TLS_PIN" >> "$INSTALL_DIR/config.txt"
        fi
        chmod 600 "$INSTALL_DIR/config.txt"
        info "TLS-пин записан в $INSTALL_DIR/config.txt"
    else
        warn "Не удалось прочитать TLS-пин — проверь $LOG_DIR/api.log (строка TLS_PIN=...) и $INSTALL_DIR/tls/api.crt"
    fi

    # Порты пользователей после перезапуска с новым шаблоном
    FAILED=$(systemctl list-units 'vkserv@*' --state=failed --no-legend 2>/dev/null | awk '{print $1}' | tr '\n' ' ')
    RUNNING=$(systemctl list-units 'vkserv@*' --state=running --no-legend 2>/dev/null | wc -l)
    info "Порты пользователей запущены: $RUNNING"
    if [ -n "${FAILED// /}" ]; then
        warn "Не запустились: $FAILED (journalctl -u <имя> -n 20)"
    fi
fi

rm -f "$INSTALL_DIR/server.bak" "$INSTALL_DIR/api.bak"

# ── Итог ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${G}✅  VKTurn обновлён до $VKSERV_VERSION${N}"
echo "   • Учёт трафика: в обе стороны, по данным самого сервера (обновление раз в 30 сек)"
echo "   • Ключи привязываются к первому устройству; отвязка — в админке"
if [ -n "${TLS_PIN:-}" ]; then
    echo ""
    echo -e "${W}TLS-пин сервера (нужен приложениям для проверки сертификата):${N}"
    echo "   $TLS_PIN"
    echo "   Он же записан в $INSTALL_DIR/config.txt (строка TLS_PIN=)."
fi
echo ""
echo -e "${Y}[!] ВАЖНО: API теперь работает ТОЛЬКО по HTTPS (https://<IP>:$API_PORT).${N}"
echo -e "${Y}    Обновите приложение-админку и перевыдайте ссылки пользователям:${N}"
echo -e "${Y}    старые http-клиенты работать не будут.${N}"
if [ "$HAS_API" = "1" ] && [ -f "$LOG_DIR/api.log" ]; then
    echo ""
    echo "Последние строки лога API:"
    tail -n 3 "$LOG_DIR/api.log" | sed 's/^/   /'
fi
