#!/bin/bash
# Проверка upgrade.sh: синтаксис + проверка "-h" новых бинарников под set -euo pipefail
cd /mnt/c/Core
bash -n upgrade.sh && echo "SYNTAX_OK"
bash -c '
set -euo pipefail
HELP=$(./dist/v1.0.2/server-linux-amd64 -h 2>&1 || true)
grep stats-file <<<"$HELP" >/dev/null && echo "server check OK"
HELP=$(./dist/v1.0.2/vkturn-api-amd64 -h 2>&1 || true)
grep -- "-bind" <<<"$HELP" >/dev/null && echo "api check OK"
'
