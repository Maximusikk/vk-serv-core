#!/bin/bash
# Проверка upgrade.sh: синтаксис + проверка "-h" новых бинарников под set -euo pipefail
# (те же grep, что делает upgrade.sh перед подменой бинарников).
# Каталог бинарников: VER=v1.1.0 bash test_upgrade.sh (по умолчанию v1.0.2).
# -tls-dir (S5/S11): upgrade.sh отвергает vkturn-api без -tls-dir. В релизах до TLS (v1.0.2, v1.1.0)
# флага нет — это ОЖИДАЕМО: скрипт печатает "api tls check: EXPECTED FAIL" и не падает,
# а итоговой строкой показывает, примет ли upgrade.sh этот бинарник. Для готового TLS-релиза
# должно быть "api tls check OK".
cd /mnt/c/Core
VER="${VER:-v1.0.2}"
bash -n upgrade.sh && echo "SYNTAX_OK"
VER="$VER" bash -c '
set -euo pipefail
echo "binaries: dist/$VER"
HELP=$(./dist/$VER/server-linux-amd64 -h 2>&1 || true)
grep stats-file <<<"$HELP" >/dev/null && echo "server check OK"
HELP=$(./dist/$VER/vkturn-api-amd64 -h 2>&1 || true)
grep -- "-bind" <<<"$HELP" >/dev/null && echo "api check OK"
if grep -- "-tls-dir" <<<"$HELP" >/dev/null; then
  echo "api tls check OK (upgrade.sh примет этот vkturn-api)"
else
  echo "api tls check: EXPECTED FAIL — в dist/$VER vkturn-api без -tls-dir (сборка до TLS)."
  echo "  upgrade.sh такой бинарник отвергнет: нужен новый релиз с TLS."
fi
'
