#!/bin/bash
# VKTurn — ротация TLS-сертификата API (S6, контракт §1 SECURITY_TLS_PLAN.md).
#
# Использование:
#   sudo bash rotate-cert.sh              # новый сертификат С ТОМ ЖЕ ключом — пин не меняется
#   sudo bash rotate-cert.sh --new-key    # новый ключ + сертификат — НОВЫЙ пин
#
# Что делает:
#   1. Бэкап текущих tls/api.crt + tls/api.key в /opt/vkturn/tls-backup/<ts>/
#   2. Генерирует новый самоподписанный сертификат (ECDSA P-256, 10 лет,
#      SAN = IP/PUBLIC_URL сервера + 127.0.0.1 + localhost) — те же параметры,
#      что у встроенной в vkturn-api генерации (api/tls.go).
#   3. Рестартует vkturn-api, ждёт health (https://127.0.0.1:7000/health), при сбое откатывает.
#   4. Пересчитывает пин (SHA-256 SPKI, строчный hex, 64 символа), пишет TLS_PIN= в config.txt
#      и печатает его. Без --new-key проверяет, что пин совпал со старым.
#
# При --new-key: пин меняется — нужно обновить админку (VKTURN_ADMIN_PIN) и перевыдать
# ссылки vkturn://...?pin=... всем пользователям (старые ссылки будут жёстко отклоняться).

set -euo pipefail

R='\033[0;31m' G='\033[0;32m' Y='\033[1;33m' W='\033[1m' N='\033[0m'
info()  { echo -e "${G}[+]${N} $*"; }
warn()  { echo -e "${Y}[!]${N} $*"; }
error() { echo -e "${R}[✗]${N} $*"; exit 1; }

INSTALL_DIR="${VKTURN_INSTALL_DIR:-/opt/vkturn}"
TLS_DIR="$INSTALL_DIR/tls"
BACKUP_DIR="$INSTALL_DIR/tls-backup"
CONFIG="$INSTALL_DIR/config.txt"
API_ENV="$INSTALL_DIR/api.env"
API_PORT="${VKTURN_API_PORT:-7000}"
VALID_DAYS=3650

# Тестовый режим (VKTURN_ROTATE_TEST=1): без root, systemctl и curl — только генерация,
# пин и config.txt во временном каталоге. На VPS не использовать.
TEST_MODE="${VKTURN_ROTATE_TEST:-0}"

NEW_KEY=0
case "${1:-}" in
    "")         NEW_KEY=0 ;;
    --new-key)  NEW_KEY=1 ;;
    *)          error "Использование: $0 [--new-key]" ;;
esac

if [ "$TEST_MODE" != "1" ] && [ "$EUID" -ne 0 ]; then
    error "Запускай от root: sudo bash $0"
fi
[ -f "$CONFIG" ] || error "VKTurn не установлен ($CONFIG нет)"
[ -f "$TLS_DIR/api.crt" ] && [ -f "$TLS_DIR/api.key" ] || \
    error "Нет пары $TLS_DIR/api.crt + api.key. Если её нет совсем — просто перезапусти vkturn-api, сертификат создастся сам; если только один файл — восстанови или удали оба"
command -v openssl &>/dev/null || error "openssl не найден"

# ── Хост для SAN: PUBLIC_URL из api.env, иначе SERVER_IP из config.txt ────────
cfg_get() { grep -m1 "^$1=" "$2" 2>/dev/null | cut -d= -f2- || true; }

PUB_HOST=$(cfg_get PUBLIC_URL "$API_ENV")
[ -z "$PUB_HOST" ] && PUB_HOST=$(cfg_get SERVER_IP "$CONFIG")
[ -z "$PUB_HOST" ] && error "Не нашёл ни PUBLIC_URL (в $API_ENV), ни SERVER_IP (в $CONFIG) — не знаю, какой IP класть в SAN"

# hostFromPublicURL ("https://1.2.3.4:7000/" → "1.2.3.4", как в api/tls.go)
PUB_HOST=$(printf '%s' "$PUB_HOST" | sed -E 's|^[a-zA-Z][a-zA-Z0-9+.-]*://||; s|[/?#].*$||; s|^\[(.*)\]:[0-9]+$|\1|; s|^([^:]+):[0-9]+$|\1|')
[ -z "$PUB_HOST" ] && error "Пустой хост из PUBLIC_URL/SERVER_IP"

# ── Пин: SHA-256 от DER SubjectPublicKeyInfo, строчный hex 64 символа ─────────
pin_of() {
    openssl x509 -in "$1" -pubkey -noout 2>/dev/null | \
        openssl pkey -pubin -outform DER 2>/dev/null | sha256sum | awk '{print $1}'
}

# ── Генерация сертификата (та же логика, что ensureCert в api/tls.go) ─────────
# generate_cert <режим: keep-key|new-key> <хост> <out.crt> <out.key> [сущест-ключ]
generate_cert() {
    local mode="$1" host="$2" outcrt="$3" outkey="$4" srckey="${5:-}"
    local san subj
    if printf '%s' "$host" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$|:.*:'; then
        san="IP:$host"
    else
        san="DNS:$host"
    fi
    san="$san,IP:127.0.0.1,DNS:localhost"
    subj="/O=VKTurn/CN=$host"

    if [ "$mode" = "keep-key" ]; then
        # Тот же ключ → тот же публичный ключ → пин не меняется.
        openssl req -x509 -new \
            -key "$srckey" -out "$outcrt" \
            -days "$VALID_DAYS" -subj "$subj" -addext "subjectAltName=$san" 2>/dev/null
        cp -p "$srckey" "$outkey"
    else
        # Новый ECDSA P-256 ключ.
        openssl req -x509 -newkey ec \
            -pkeyopt ec_paramgen_curve:P-256 -nodes \
            -keyout "$outkey" -out "$outcrt" \
            -days "$VALID_DAYS" -subj "$subj" -addext "subjectAltName=$san" 2>/dev/null
    fi
    chmod 600 "$outkey"
    chmod 644 "$outcrt"
}

OLD_PIN=$(pin_of "$TLS_DIR/api.crt")
[ -n "$OLD_PIN" ] || error "Не удалось вычислить пин текущего сертификата"

TS=$(date +%Y%m%d-%H%M%S)
info "Текущий пин: $OLD_PIN"
if [ "$NEW_KEY" = 1 ]; then
    info "Режим: НОВЫЙ ключ (пин изменится)"
else
    info "Режим: тот же ключ (пин не изменится)"
fi

# ── 1. Бэкап старых файлов ────────────────────────────────────────────────────
BAK="$BACKUP_DIR/$TS"
mkdir -p "$BAK"
chmod 700 "$BACKUP_DIR" "$BAK"
cp -p "$TLS_DIR/api.crt" "$TLS_DIR/api.key" "$BAK/"
chmod 600 "$BAK/api.key" "$BAK/api.crt"
info "Бэкап старых файлов: $BAK"

# ── 2. Генерация нового сертификата ──────────────────────────────────────────
NEWCRT="$TLS_DIR/api.crt.new"
NEWKEY="$TLS_DIR/api.key.new"
rm -f "$NEWCRT" "$NEWKEY"
if ! generate_cert "$([ "$NEW_KEY" = 1 ] && echo new-key || echo keep-key)" \
                   "$PUB_HOST" "$NEWCRT" "$NEWKEY" "$TLS_DIR/api.key"; then
    rm -f "$NEWCRT" "$NEWKEY"
    error "openssl не смог сгенерировать сертификат (хост: $PUB_HOST)"
fi

# Проверяем, что это ECDSA P-256 и ключ/сертификат согласованы
openssl x509 -in "$NEWCRT" -noout -text 2>/dev/null | grep -q "prime256v1" || {
    rm -f "$NEWCRT" "$NEWKEY"; error "Новый сертификат не ECDSA P-256 — отмена"; }
[ "$(openssl x509 -in "$NEWCRT" -pubkey -noout | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum | awk '{print $1}')" = "$(openssl pkey -in "$NEWKEY" -pubout -outform DER 2>/dev/null | sha256sum | awk '{print $1}')" ] || {
    rm -f "$NEWCRT" "$NEWKEY"; error "Ключ и сертификат не согласованы — отмена"; }

NEW_PIN=$(pin_of "$NEWCRT")

# Подмена файлов (атомарно: сначала ключ, потом сертификат)
install -m 600 "$NEWKEY" "$TLS_DIR/api.key"
install -m 644 "$NEWCRT" "$TLS_DIR/api.crt"
rm -f "$NEWCRT" "$NEWKEY"
chmod 700 "$TLS_DIR"

if [ "$NEW_KEY" = 0 ]; then
    if [ "$NEW_PIN" != "$OLD_PIN" ]; then
        warn "Пин изменился без --new-key (${NEW_PIN} вместо ${OLD_PIN}) — ключ был не тем? Восстанавливаю бэкап"
        cp -p "$BAK/api.crt" "$TLS_DIR/api.crt"; cp -p "$BAK/api.key" "$TLS_DIR/api.key"
        error "Откат выполнен, пин прежний: $OLD_PIN"
    fi
    info "Пин не изменился: $NEW_PIN"
fi

# ── 3. Рестарт API + health ───────────────────────────────────────────────────
rollback() {
    warn "Откат: восстанавливаю файлы из $BAK и перезапускаю vkturn-api"
    cp -p "$BAK/api.crt" "$TLS_DIR/api.crt"; chmod 644 "$TLS_DIR/api.crt"
    cp -p "$BAK/api.key" "$TLS_DIR/api.key"; chmod 600 "$TLS_DIR/api.key"
    if [ "$TEST_MODE" != "1" ]; then
        systemctl restart vkturn-api || warn "Не удалось перезапустить vkturn-api — проверь вручную: journalctl -u vkturn-api -n 20"
    fi
}

if [ "$TEST_MODE" = "1" ]; then
    info "(тест) рестарт vkturn-api и health-проверка пропущены"
else
    if ! systemctl restart vkturn-api; then
        rollback
        error "systemctl restart vkturn-api не удался"
    fi
    HEALTH_OK=0
    for _ in $(seq 1 12); do
        if curl -fsS --max-time 5 -k "https://127.0.0.1:$API_PORT/health" &>/dev/null; then
            HEALTH_OK=1; break
        fi
        sleep 1
    done
    if [ "$HEALTH_OK" != 1 ]; then
        rollback
        error "API не отвечает на https://127.0.0.1:$API_PORT/health после ротации — откат выполнен"
    fi
    info "vkturn-api: running ✓ (https://127.0.0.1:$API_PORT/health)"
fi

# ── 4. Пин в config.txt и вывод ───────────────────────────────────────────────
if grep -q '^TLS_PIN=' "$CONFIG" 2>/dev/null; then
    sed -i "s|^TLS_PIN=.*|TLS_PIN=$NEW_PIN|" "$CONFIG"
else
    echo "TLS_PIN=$NEW_PIN" >> "$CONFIG"
fi
chmod 600 "$CONFIG"
info "TLS_PIN записан в $CONFIG"

echo
info "Пин (SPKI SHA-256): $NEW_PIN"
if [ "$NEW_KEY" = 1 ]; then
    warn "ПИН ИЗМЕНИЛСЯ. Обязательно:"
    echo "  1. Обнови пин в админке (или перечитай VKTURN_ADMIN_PIN при следующем SSH-подключении)."
    echo "  2. Перевыдай ссылки vkturn://...?pin=... пользователям — старые ссылки будут жёстко отклоняться."
    echo "  3. Проверка curl: curl --pinnedpubkey sha256//\$(openssl x509 -in $TLS_DIR/api.crt -pubkey -noout | openssl pkey -pubin -outform DER | openssl dgst -sha256 -binary | openssl base64 -A) -k https://$(cfg_get SERVER_IP "$CONFIG"):$API_PORT/health"
else
    echo "  Пин прежний — ссылки и админка продолжат работать без изменений."
fi
info "Бэкап прежних файлов (можно удалить): $BAK"
