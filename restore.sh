#!/bin/bash
# VKTurn — восстановление из бэкапа (G4).
#
# Использование (на НОВОМ или на том же VPS):
#   sudo bash restore.sh /opt/vkturn/backups/vkturn-YYYYMMDD-HHMMSS.tar.gz
#
# Миграция на новый VPS:
#   1. На старом:   sudo bash backup.sh
#   2. Скопировать: scp /opt/vkturn/backups/vkturn-*.tar.gz root@<новый>:/root/
#   3. На новом:    install.sh (https://raw.githubusercontent.com/Maximusikk/vk-serv-core/main/install.sh | bash)
#      — сгенерирует СВОИ пароли, они будут перезаписаны шагом 4.
#   4. На новом:    sudo bash restore.sh /root/vkturn-*.tar.gz
#      — вернёт базу, config.txt, users/ и подгонит под config.txt пароли hysteria/vkserv и токены API.
#   5. В админке обновить serverUrl на новый IP (или в ссылках vkturn:// — у ключей ссылка
#      содержит старый IP, пользователям нужно вставить ссылку заново или продавец разошлёт новые).
#
# Внимание: config.txt из бэкапа содержит SERVER_IP старого сервера. Если IP изменился,
# скрипт спросит, заменить ли его на IP этого VPS.

set -euo pipefail

R='\033[0;31m' G='\033[0;32m' Y='\033[1;33m' W='\033[1m' N='\033[0m'
info()  { echo -e "${G}[+]${N} $*"; }
warn()  { echo -e "${Y}[!]${N} $*"; }
error() { echo -e "${R}[✗]${N} $*"; exit 1; }

INSTALL_DIR="/opt/vkturn"

[ $EUID -ne 0 ] && error "Запускай от root: sudo bash $0"
[ -n "${1:-}" ] || error "Укажи архив: $0 <vkturn-YYYYMMDD-HHMMSS.tar.gz>"
[ -f "$1" ] || error "Архив не найден: $1"
[ -d "$INSTALL_DIR" ] || error "VKTurn не установлен — сначала install.sh, потом restore"

# Проверяем содержимое архива до распаковки
TAR_LIST=$(tar -tzf "$1") || error "Архив повреждён: $1"
grep -q "api.db" <<<"$TAR_LIST" || error "В архиве нет api.db"
grep -q "config.txt" <<<"$TAR_LIST" || error "В архиве нет config.txt"

warn "Восстановление перезапишет api.db, config.txt и users/ текущей установки"
read -r -p "Продолжить? [y/N] " yn
[ "$yn" = "y" ] || exit 1

step() { echo -e "\n${W}━━━ $* ━━━${N}"; }
step "Остановка сервисов"
systemctl stop vkturn-api || true

STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
tar -xzf "$1" -C "$STAGE"
chmod 600 "$STAGE/api.db" "$STAGE/config.txt" 2>/dev/null || true

step "Восстановление базы и конфига"
cp "$STAGE/api.db" "$INSTALL_DIR/api.db"
cp "$STAGE/config.txt" "$INSTALL_DIR/config.txt"
chmod 600 "$INSTALL_DIR/api.db" "$INSTALL_DIR/config.txt"

if [ -d "$STAGE/users" ]; then
    mkdir -p "$INSTALL_DIR/users"
    cp -r "$STAGE/users/." "$INSTALL_DIR/users/"
    chmod 750 "$INSTALL_DIR/users"
    chmod 640 "$INSTALL_DIR/users/"* 2>/dev/null || true
fi

# SERVER_IP из бэкапа может не соответствовать этому VPS
OLD_IP=$(grep '^SERVER_IP=' "$INSTALL_DIR/config.txt" | cut -d= -f2)
CUR_IP=$(ip -4 addr show scope global 2>/dev/null | awk '/inet /{split($2,a,"/"); print a[1]; exit}')
if [ -n "$CUR_IP" ] && [ "$OLD_IP" != "$CUR_IP" ]; then
    warn "В бэкапе SERVER_IP=$OLD_IP, а этот сервер: $CUR_IP"
    read -r -p "Заменить SERVER_IP на $CUR_IP? [Y/n] " yn
    if [ "$yn" != "n" ]; then
        sed -i "s|^SERVER_IP=.*|SERVER_IP=$CUR_IP|" "$INSTALL_DIR/config.txt"
        info "SERVER_IP обновлён: $CUR_IP"
        warn "Конфиги пользователей содержат старый IP — покупателям нужна новая ссылка (unbind → повторная активация, или разошли vkturn:// ссылки заново)"
    fi
fi

# G10: install.sh на новом VPS сгенерировал СВОИ пароли и токены (hy2.yaml, юнит vkturn-server, api.env),
# а config.txt из бэкапа содержит СТАРЫЕ. API строит клиентские конфиги из config.txt, поэтому без
# синхронизации у клиентов не пройдёт авторизация hysteria, а токен продавца перестанет подходить.
# Источник истины — config.txt: подгоняем под него сервисы.
step "Синхронизация паролей и токенов с config.txt"
cfg_get() { grep -m1 "^$1=" "$INSTALL_DIR/config.txt" | cut -d= -f2- || true; }
is_safe() { [[ "$1" =~ ^[A-Za-z0-9]+$ ]]; }   # значения из архива попадают в sed — только буквы/цифры
set_env() { # FILE KEY VALUE
    if grep -q "^$2=" "$1"; then sed -i "s|^$2=.*|$2=$3|" "$1"; else echo "$2=$3" >> "$1"; fi
}
RS_HY2=$(cfg_get HY2_PASS)
RS_WRAP=$(cfg_get WRAP_PASS)
RS_ADMIN=$(cfg_get ADMIN_TOKEN)
RS_INT=$(cfg_get INTERNAL_SECRET)

if is_safe "$RS_HY2" && [ -f "$INSTALL_DIR/hy2.yaml" ]; then
    sed -i -E "s|^(  password: ).*|\\1\"$RS_HY2\"|" "$INSTALL_DIR/hy2.yaml"
    info "hy2.yaml: пароль из config.txt"
else
    warn "HY2_PASS не применён (нет в config.txt или нет hy2.yaml) — клиенты могут не авторизоваться"
fi

SRV_UNIT="/etc/systemd/system/vkturn-server.service"
if is_safe "$RS_WRAP" && [ -f "$SRV_UNIT" ]; then
    sed -i -E "s|^(  -password ).*|\\1\"$RS_WRAP\"|" "$SRV_UNIT"
    info "vkturn-server: пароль из config.txt"
else
    warn "WRAP_PASS не применён (нет в config.txt или нет $SRV_UNIT)"
fi

if [ -f "$INSTALL_DIR/api.env" ]; then
    if is_safe "$RS_ADMIN" && is_safe "$RS_INT"; then
        set_env "$INSTALL_DIR/api.env" ADMIN_TOKEN "$RS_ADMIN"
        set_env "$INSTALL_DIR/api.env" INTERNAL_SECRET "$RS_INT"
        chmod 600 "$INSTALL_DIR/api.env"
        info "api.env: токены из config.txt (токен продавца прежний)"
    else
        warn "ADMIN_TOKEN/INTERNAL_SECRET не применены (нет в config.txt) — токен на этом сервере новый, смотри api.env"
    fi
fi

step "Перезапуск"
systemctl daemon-reload
systemctl restart vkturn-server vkturn-hy2 vkturn-api 2>/dev/null || true
sleep 3
systemctl is-active --quiet vkturn-api && info "vkturn-api: running ✓" || warn "vkturn-api не запустился — journalctl -u vkturn-api -n 20"

# API при старте сам пересоберёт шаблон vkserv@ и поднимет порты ключей с port IS NOT NULL
RUNNING=$(systemctl list-units 'vkserv@*' --state=running --no-legend 2>/dev/null | wc -l)
info "Порты пользователей запущены: $RUNNING"
echo -e "${G}✅  Восстановление завершено${N}"
