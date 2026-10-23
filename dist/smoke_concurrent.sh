#!/bin/bash
set -euo pipefail
D=$(mktemp -d)
mkdir -p "$D/users"
printf 'SERVER_IP=127.0.0.1\nHY2_PASS=testpass\nVK_LINK=https://vk.com/call/join/TEST\n' > "$D/config.txt"
/mnt/c/Core/dist/vkturn-api-amd64 -db "$D/api.db" -dir "$D" -port 17001 -admin-token ADMIN123 -internal-secret INT123 >"$D/log" 2>&1 &
P=$!
sleep 2
KEYS=()
for i in {1..20}; do
  RES=$(curl -s -X POST "http://localhost:17001/admin/keys/create" -H "X-Admin-Token: ADMIN123" -d '{"expires_days":1}')
  KEY=$(echo "$RES" | sed -n 's/.*"key":"\([^"]*\)".*/\1/p')
  if [ -z "$KEY" ]; then echo "Failed to create key $i"; kill $P 2>/dev/null || true; rm -rf "$D"; exit 1; fi
  KEYS+=("$KEY")
done
echo "Created 20 keys. Activating in parallel..."
for i in "${!KEYS[@]}"; do
  curl -s -X POST "http://localhost:17001/activate" -d "{\"key\":\"${KEYS[$i]}\", \"device_id\":\"device_$i\"}" > "$D/res_$i.json" &
done
wait
echo "Checking ports..."
> "$D/ports.txt"
for key in "${KEYS[@]}"; do
  RES=$(curl -s "http://localhost:17001/admin/keys/$key" -H "X-Admin-Token: ADMIN123")
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
  kill $P 2>/dev/null || true; rm -rf "$D"; exit 1
fi
kill $P 2>/dev/null || true
rm -rf "$D"
echo "Smoke concurrent test passed."
