#!/bin/bash
# VKTurn — бэкап (G4): sqlite .backup + users/, config.txt и tls/ (сертификат+ключ), хранить 7 последних.
#
# Использование:
#   sudo bash backup.sh              # разовый бэкап в /opt/vkturn/backups/
#   sudo bash backup.sh --install    # + поставить systemd timer раз в сутки
#
# Восстановление на новом VPS: restore.sh <архив.tar.gz> (см. его шапку).

set -euo pipefail

R='\033[0;31m' G='\033[0;32m' Y='\033[1;33m' W='\033[1m' N='\033[0m'
info()  { echo -e "${G}[+]${N} $*"; }
warn()  { echo -e "${Y}[!]${N} $*"; }
error() { echo -e "${R}[✗]${N} $*"; exit 1; }

INSTALL_DIR="/opt/vkturn"
BACKUP_DIR="$INSTALL_DIR/backups"
KEEP=7
DB="$INSTALL_DIR/api.db"

[ $EUID -ne 0 ] && error "Запускай от root: sudo bash $0"
[ -f "$INSTALL_DIR/config.txt" ] || error "VKTurn не установлен ($INSTALL_DIR/config.txt нет)"

# ── Сам бэкап ─────────────────────────────────────────────────────────────────

TS=$(date +%Y%m%d-%H%M%S)
OUT="$BACKUP_DIR/vkturn-$TS.tar.gz"
# Каталог должен существовать ДО mktemp (иначе первый запуск падает), права 700: внутри секреты
mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"
STAGE=$(mktemp -d "$BACKUP_DIR/.stage.XXXXXX")
trap 'rm -rf "$STAGE"' EXIT

# База: через sqlite3 .backup (консистентный снапшот при живом API).
# Fallback — прямое копирование: WAL может потерять последние секунды, но не сломает базу.
if command -v sqlite3 &>/dev/null; then
    sqlite3 "$DB" ".backup '$STAGE/api.db'"
else
    warn "sqlite3 не найден — копирую api.db напрямую (перезапуск vkturn-api перед restore желателен)"
    cp "$DB" "$STAGE/api.db"
fi
chmod 600 "$STAGE/api.db"

# Конфиг (секреты) и каталог users/
cp "$INSTALL_DIR/config.txt" "$STAGE/config.txt"
chmod 600 "$STAGE/config.txt"
if [ -d "$INSTALL_DIR/users" ]; then
    cp -r "$INSTALL_DIR/users" "$STAGE/users"
    chmod 750 "$STAGE/users"
fi

# TLS-сертификат и ключ (S6): без них на новом сервере сменит пин (ключ генерится заново),
# приложения с запомненным пином (TOFU) перестанут подключаться.
if [ -f "$INSTALL_DIR/tls/api.crt" ] && [ -f "$INSTALL_DIR/tls/api.key" ]; then
    mkdir -p "$STAGE/tls"
    cp -p "$INSTALL_DIR/tls/api.crt" "$INSTALL_DIR/tls/api.key" "$STAGE/tls/"
    chmod 700 "$STAGE/tls"
    chmod 644 "$STAGE/tls/api.crt"
    chmod 600 "$STAGE/tls/api.key"
fi

TARLIST=(api.db config.txt)
[ -d "$STAGE/users" ] && TARLIST+=(users)
[ -d "$STAGE/tls" ] && TARLIST+=(tls)
tar -czf "$OUT" -C "$STAGE" "${TARLIST[@]}"
chmod 600 "$OUT"
rm -rf "$STAGE"

# Ротация: оставляем KEEP последних
ls -1t "$BACKUP_DIR"/vkturn-*.tar.gz 2>/dev/null | tail -n +$((KEEP + 1)) | while read -r old; do
    rm -f "$old"
    info "Удалён старый бэкап: $(basename "$old")"
done

SIZE=$(du -h "$OUT" | cut -f1)
info "Бэкап готов: $OUT ($SIZE)"

# ── Установка systemd timer (раз в сутки, G4) ─────────────────────────────────

if [ "${1:-}" = "--install" ]; then
    SELF=$(readlink -f "$0")
    cp -f "$SELF" "$INSTALL_DIR/backup.sh" && chmod 700 "$INSTALL_DIR/backup.sh"
    cat > /etc/systemd/system/vkturn-backup.service << EOF
[Unit]
Description=VKTurn daily backup

[Service]
Type=oneshot
ExecStart=$INSTALL_DIR/backup.sh
EOF
    cat > /etc/systemd/system/vkturn-backup.timer << EOF
[Unit]
Description=VKTurn daily backup timer

[Timer]
OnCalendar=*-*-* 04:30:00
Persistent=true

[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload
    systemctl enable --now vkturn-backup.timer
    info "Timer установлен: vkturn-backup.timer (ежедневно в 04:30)"
fi
