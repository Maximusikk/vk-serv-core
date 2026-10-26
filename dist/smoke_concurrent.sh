#!/bin/bash
# Smoke: 20 параллельных /activate получают 20 разных портов.
# API слушает только HTTPS (S1): сертификат создаётся в $D/tls, curl -k допустим — только loopback 127.0.0.1.
# Бинарник собирается из текущих исходников (в dist старая сборка без -tls-dir).
set -euo pipefail
export GOROOT=$HOME/go GOPATH=$HOME/gopath GOCACHE=$HOME/.cache/go-build
export PATH=$GOROOT/bin:$GOPATH/bin:$PATH
cd /mnt/c/Core
D=$(mktemp -d)
mkdir -p "$D/users"
go build -C ./api -o "$D/api" .
# без systemd (WSL) API запускает $D/server напрямую — нужен рядом
go build -o "$D/server" ./server
# убрать API и запущенные им server при любом выходе
cleanup() { kill "${P:-}" 2>/dev/null || true; pkill -f "$D/server" 2>/dev/null || true; rm -rf "$D"; }
trap cleanup EXIT
printf 'SERVER_IP=127.0.0.1\nHY2_PASS=testpass\nVK_LINK=https://vk.com/call/join/TEST\n' > "$D/config.txt"
"$D/api" -db "$D/api.db" -dir "$D" -tls-dir "$D/tls" -port 17001 -activate-rate 100 -admin-token ADMIN123 -internal-secret INT123 >"$D/log" 2>&1 &
# -activate-rate 100: все 20 запросов с 127.0.0.1, а лимит по умолчанию — 10/мин с IP
P=$!
API=https://127.0.0.1:17001
c() { curl -sk "$@"; }
for _i in $(seq 1 20); do c -fsS --max-time 2 "$API/health" >/dev/null 2>&1 && break; sleep 0.5; done
KEYS=()
for i in {1..20}; do
  RES=$(c -X POST "$API/admin/keys/create" -H "X-Admin-Token: ADMIN123" -d '{"expires_days":1}')
  KEY=$(echo "$RES" | sed -n 's/.*"key":"\([^"]*\)".*/\1/p')
  if [ -z "$KEY" ]; then echo "Failed to create key $i"; kill $P 2>/dev/null || true; rm -rf "$D"; exit 1; fi
  KEYS+=("$KEY")
done
echo "Created 20 keys. Activating in parallel..."
CPIDS=()
for i in "${!KEYS[@]}"; do
  c --max-time 30 -X POST "$API/activate" -d "{\"key\":\"${KEYS[$i]}\", \"device_id\":\"device_$i\"}" > "$D/res_$i.json" &
  CPIDS+=($!)
done
# ждём только curl: голый `wait` ждал бы и фоновый API (зависание)
wait "${CPIDS[@]}" || true
echo "Checking ports..."
> "$D/ports.txt"
for key in "${KEYS[@]}"; do
  RES=$(c "$API/admin/keys/$key" -H "X-Admin-Token: ADMIN123")
  PORT=$(echo "$RES" | sed -n 's/.*"port":\([0-9]*\).*/\1/p')
  if [ -n "$PORT" ]; then echo "$PORT" >> "$D/ports.txt"; else echo "WARNING: Key $key has no port!"; fi
done
TOTAL_PORTS=$(wc -l < "$D/ports.txt")
UNIQUE_PORTS=$(sort -u "$D/ports.txt" | wc -l)
echo "Total ports assigned: $TOTAL_PORTS"
echo "Unique ports: $UNIQUE_PORTS"
if [ "$TOTAL_PORTS" -eq 20 ] && [ "$UNIQUE_PORTS" -eq 20 ]; then
  echo "SUCCESS: All 20 activations got unique ports."
else
  echo "FAILURE: Port collision or missing ports detected."
  cat "$D/ports.txt"
  echo "Activation errors (count, body):"
  cat "$D"/res_*.json | grep '"error"' | sort | uniq -c || true
  kill $P 2>/dev/null || true; rm -rf "$D"; exit 1
fi
kill $P 2>/dev/null || true
wait $P 2>/dev/null || true
rm -rf "$D"
echo "Smoke concurrent test passed."
