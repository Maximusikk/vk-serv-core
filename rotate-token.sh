#!/bin/bash
# VKTurn — смена токена администратора (если токен утёк).
# Меняет ADMIN_TOKEN сразу в двух местах: /opt/vkturn/api.env (его читает API)
# и /opt/vkturn/config.txt (из него токен берёт restore.sh при переезде).
# Если токены в двух файлах разойдутся, при переезде вернётся старый токен.
#
# Использование:
#   sudo bash rotate-token.sh            # сгенерировать новый токен
#   sudo bash rotate-token.sh <токен>    # задать свой (буквы и цифры, от 24 символов)
#
# После смены обновите токен в боте и в приложении-админке: старый перестаёт работать.

set -euo pipefail

R='\033[0;31m' G='\033[0;32m' Y='\033[1;33m' N='\033[0m'
info()  { echo -e "${G}[+]${N} $*"; }
warn()  { echo -e "${Y}[!]${N} $*"; }
error() { echo -e "${R}[✗]${N} $*"; exit 1; }

INSTALL_DIR="/opt/vkturn"
ENV_FILE="$INSTALL_DIR/api.env"
CFG_FILE="$INSTALL_DIR/config.txt"
API_PORT=7000

[ $EUID -ne 0 ] && error "Запускай от root: sudo bash $0"
[ -f "$ENV_FILE" ] || error "Нет $ENV_FILE — API не установлен или старая установка (сначала upgrade.sh)"
[ -f "$CFG_FILE" ] || error "Нет $CFG_FILE"

OLD=$(grep -m1 '^ADMIN_TOKEN=' "$ENV_FILE" | cut -d= -f2- || true)
[ -n "$OLD" ] || error "В $ENV_FILE нет ADMIN_TOKEN"

NEW="${1:-$(openssl rand -hex 24)}"
[[ "$NEW" =~ ^[A-Za-z0-9]{24,}$ ]] || error "Токен: только буквы и цифры, не короче 24 символов"
[ "$NEW" != "$OLD" ] || error "Новый токен совпадает со старым"

# Запись токена: заменяем строку или добавляем, если её нет
put_token() { # FILE VALUE
    if grep -q '^ADMIN_TOKEN=' "$1"; then
        sed -i "s|^ADMIN_TOKEN=.*|ADMIN_TOKEN=$2|" "$1"
    else
        echo "ADMIN_TOKEN=$2" >> "$1"
    fi
}

put_token "$ENV_FILE" "$NEW"
put_token "$CFG_FILE" "$NEW"
chmod 600 "$ENV_FILE" "$CFG_FILE"

systemctl restart vkturn-api || true
sleep 2

# Проверка: новый токен принят, старый отвергнут. При сбое возвращаем старый.
code_new=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 -k \
    -H "X-Admin-Token: $NEW" "https://127.0.0.1:$API_PORT/admin/health" || true)
if [ "$code_new" != "200" ]; then
    warn "Новый токен не принят (HTTP $code_new) — возвращаю старый"
    put_token "$ENV_FILE" "$OLD"
    put_token "$CFG_FILE" "$OLD"
    systemctl restart vkturn-api || true
    error "Токен не изменён. Лог: journalctl -u vkturn-api -n 30"
fi
code_old=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 -k \
    -H "X-Admin-Token: $OLD" "https://127.0.0.1:$API_PORT/admin/health" || true)
[ "$code_old" = "401" ] || warn "Старый токен дал HTTP $code_old (ожидалось 401) — проверь вручную"

info "Токен заменён в api.env и config.txt, vkturn-api перезапущен"
echo ""
echo "Новый токен администратора:"
echo "$NEW"
echo ""
echo "Обновите его в боте и в приложении-админке."
