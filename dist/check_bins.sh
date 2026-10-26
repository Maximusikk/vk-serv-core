#!/bin/bash
# Наличие фич в бинарниках релиза. tls-dir>0 у vkturn-api = сборка с HTTPS (S1); у server всегда 0.
# Другой релиз: VER=v1.1.0 bash check_bins.sh (по умолчанию v1.0.2).
cd /mnt/c/Core/dist/${VER:-v1.0.2}
for f in *; do
  printf '%-20s stats-file=%s unbind=%s tls-dir=%s\n' "$f" "$(grep -c stats-file "$f")" "$(grep -c unbind "$f")" "$(grep -c -- -tls-dir "$f")"
done
sha256sum *
