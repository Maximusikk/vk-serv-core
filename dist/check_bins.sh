#!/bin/bash
cd /mnt/c/Core/dist/v1.0.2
for f in *; do
  printf '%-20s stats-file=%s unbind=%s\n' "$f" "$(grep -c stats-file "$f")" "$(grep -c unbind "$f")"
done
sha256sum *
