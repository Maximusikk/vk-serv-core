#!/bin/bash
# Smoke: /activate без vk_link должен пройти VK-проверку (дальше упрётся в systemctl — это ок в WSL)
set -u
sha256sum /mnt/c/Core/dist/v1.0.2/vkturn-api-*
D=$(mktemp -d)
mkdir -p "$D/users"
printf 'SERVER_IP=1.2.3.4\nHY2_PASS=x\nVK_LINK=https://vk.com/call/join/TEST\n' > "$D/config.txt"
/mnt/c/Core/dist/v1.0.2/vkturn-api-amd64 -db "$D/api.db" -dir "$D" -port 17000 -admin-token A -internal-secret I >"$D/log" 2>&1 &
P=$!; sleep 1
KEY=$(curl -s -X POST localhost:17000/admin/keys/create -H 'X-Admin-Token: A' -d '{"expires_days":1}' | sed -n 's/.*"key":"\([^"]*\)".*/\1/p')
echo "key=$KEY"
echo "--- with server VK_LINK, no vk_link in request:"
curl -s -X POST localhost:17000/activate -d "{\"key\":\"${KEY^^}\"}"; echo
echo "--- server without VK_LINK, no vk_link:"
sed -i '/VK_LINK/d' "$D/config.txt"
curl -s -X POST localhost:17000/activate -d "{\"key\":\"$KEY\"}"; echo
echo "--- /internal/traffic from non-loopback is covered by code; admin bad token:"
curl -s -o /dev/null -w "%{http_code}\n" localhost:17000/admin/keys -H 'X-Admin-Token: B'
kill $P; rm -rf "$D"
