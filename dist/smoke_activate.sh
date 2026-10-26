#!/bin/bash
# Smoke: /activate без vk_link должен пройти VK-проверку (дальше упрётся в systemctl — это ок в WSL)
# API слушает только HTTPS (S1): сертификат создаётся в $D/tls, curl -k допустим — только loopback 127.0.0.1.
# Бинарник собирается из текущих исходников (в dist/v1.0.2 старая сборка без -tls-dir).
set -u
export GOROOT=$HOME/go GOPATH=$HOME/gopath GOCACHE=$HOME/.cache/go-build
export PATH=$GOROOT/bin:$GOPATH/bin:$PATH
cd /mnt/c/Core
D=$(mktemp -d)
mkdir -p "$D/users"
go build -C ./api -o "$D/api" . || { echo "go build failed"; rm -rf "$D"; exit 1; }
printf 'SERVER_IP=1.2.3.4\nHY2_PASS=x\nVK_LINK=https://vk.com/call/join/TEST\n' > "$D/config.txt"
"$D/api" -db "$D/api.db" -dir "$D" -tls-dir "$D/tls" -port 17000 -admin-token A -internal-secret I >"$D/log" 2>&1 &
P=$!
API=https://127.0.0.1:17000
c() { curl -sk "$@"; }
for _i in $(seq 1 20); do c -fsS --max-time 2 "$API/health" >/dev/null 2>&1 && break; sleep 0.5; done
KEY=$(c -X POST "$API/admin/keys/create" -H 'X-Admin-Token: A' -d '{"expires_days":1}' | sed -n 's/.*"key":"\([^"]*\)".*/\1/p')
echo "key=$KEY"
echo "--- with server VK_LINK, no vk_link in request:"
c -X POST "$API/activate" -d "{\"key\":\"${KEY^^}\",\"device_id\":\"smoke-dev\"}"; echo
echo "--- server without VK_LINK, no vk_link:"
sed -i '/VK_LINK/d' "$D/config.txt"
c -X POST "$API/activate" -d "{\"key\":\"$KEY\",\"device_id\":\"smoke-dev\"}"; echo
echo "--- /internal/traffic from non-loopback is covered by code; admin bad token:"
c -o /dev/null -w "%{http_code}\n" "$API/admin/keys" -H 'X-Admin-Token: B'
echo "--- plain HTTP must not be served:"
curl -s -o /dev/null -w "%{http_code}\n" --max-time 3 http://127.0.0.1:17000/health || true
kill $P; wait $P 2>/dev/null; rm -rf "$D"
