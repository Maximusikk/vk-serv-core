#!/bin/bash
# VKTurn — трекер трафика
# Читает байты iptables по каждому юзерскому порту и отправляет в API.
# Запускается cron каждые 30 секунд (см. установку в install.sh).
#
# Установка cron:
#   * * * * * /opt/vkturn/tracker.sh
#   * * * * * sleep 30; /opt/vkturn/tracker.sh

set -euo pipefail

INSTALL_DIR="/opt/vkturn"
API_URL="http://127.0.0.1:7000"
USERS_DIR="$INSTALL_DIR/users"
INTERNAL_SECRET=""

# Читаем INTERNAL_SECRET из конфига
if [ -f "$INSTALL_DIR/config.txt" ]; then
    INTERNAL_SECRET=$(grep '^INTERNAL_SECRET=' "$INSTALL_DIR/config.txt" | cut -d= -f2-)
fi

if [ -z "$INTERNAL_SECRET" ]; then
    echo "[tracker] ERROR: INTERNAL_SECRET not found in $INSTALL_DIR/config.txt" >&2
    exit 1
fi

# Нет юзеров — выходим тихо
[ -d "$USERS_DIR" ] || exit 0
shopt -s nullglob
confs=("$USERS_DIR"/*.conf)
[ ${#confs[@]} -eq 0 ] && exit 0

# Читаем всю таблицу INPUT один раз (дешевле чем N вызовов iptables)
IPTABLES_OUT=$(iptables -L INPUT -n -v --line-numbers 2>/dev/null || true)

for conf in "${confs[@]}"; do
    PORT=$(grep '^PORT=' "$conf" 2>/dev/null | cut -d= -f2-)
    [ -z "$PORT" ] && continue
    [[ "$PORT" =~ ^[0-9]+$ ]] || continue

    # Ищем строку с dpt:PORT в кэшированном выводе iptables
    # Формат: pkts bytes target prot opt in out source destination
    BYTES=$(echo "$IPTABLES_OUT" | awk -v port="$PORT" '
        $0 ~ "dpt:" port " " || $0 ~ "dpt:" port "$" {
            # bytes — второй столбец, может быть K/M суффикс
            val = $2
            if (val ~ /K$/) { sub(/K$/, "", val); val = val * 1024 }
            if (val ~ /M$/) { sub(/M$/, "", val); val = val * 1024 * 1024 }
            if (val ~ /G$/) { sub(/G$/, "", val); val = val * 1024 * 1024 * 1024 }
            print int(val)
            exit
        }
    ')

    [ -z "$BYTES" ] && BYTES=0
    [ "$BYTES" -eq 0 ] && continue  # Нет трафика — пропускаем

    # Отправляем в API
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST "$API_URL/internal/traffic" \
        -H "Content-Type: application/json" \
        -H "X-Internal: $INTERNAL_SECRET" \
        -d "{\"port\": $PORT, \"bytes\": $BYTES}" \
        --max-time 5 2>/dev/null || echo "000")

    if [ "$HTTP_CODE" = "200" ]; then
        # Сбрасываем счётчик ТОЛЬКО этого правила чтобы не трогать остальные
        iptables -Z INPUT $(iptables -L INPUT --line-numbers -n 2>/dev/null | \
            awk -v port="$PORT" '$0 ~ "dpt:" port { print $1; exit }') 2>/dev/null || true
    else
        echo "[tracker] WARNING: API returned $HTTP_CODE for port $PORT" >&2
    fi
done
