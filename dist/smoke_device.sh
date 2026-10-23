#!/bin/bash
# Smoke: server пишет stats-файл; API: привязка ключа к устройству и отвязка
export GOROOT=$HOME/go GOPATH=$HOME/gopath GOCACHE=$HOME/.cache/go-build
export PATH=$GOROOT/bin:$GOPATH/bin:$PATH
cd /mnt/c/Core
D=$(mktemp -d); mkdir -p "$D/users"

echo "== server stats-file"
go build -o "$D/server" ./server
"$D/server" -listen 127.0.0.1:56999 -connect 127.0.0.1:1 -wrap -password x -stats-file "$D/users/56999.stats" >/dev/null 2>&1 &
SP=$!; sleep 2; echo "stats: $(cat "$D/users/56999.stats" 2>/dev/null || echo MISSING)"
kill $SP; wait $SP 2>/dev/null

echo "== api device binding"
go build -C ./api -o "$D/api" .
printf 'SERVER_IP=1.2.3.4\nHY2_PASS=x\nVK_LINK=https://vk.com/call/join/TEST\n' > "$D/config.txt"
"$D/api" -db "$D/api.db" -dir "$D" -port 17001 -admin-token A -internal-secret I >"$D/api.log" 2>&1 &
AP=$!; sleep 1
KEY=$(curl -s -X POST localhost:17001/admin/keys/create -H 'X-Admin-Token: A' -d '{"expires_days":1}' | sed -n 's/.*"key":"\([^"]*\)".*/\1/p')
act() { curl -s -X POST localhost:17001/activate -d "{\"key\":\"$KEY\"$1}"; echo; }
echo -n "no device_id      : "; act ''
echo -n "device A (binds)  : "; act ',"device_id":"AAA"'
echo -n "device B          : "; act ',"device_id":"BBB"'
echo -n "list device_bound : "; curl -s localhost:17001/admin/keys -H 'X-Admin-Token: A' | grep -o '"device_bound":[a-z]*'
echo -n "unbind            : "; curl -s -X POST localhost:17001/admin/keys/$KEY/unbind -H 'X-Admin-Token: A'; echo
echo -n "device B after    : "; act ',"device_id":"BBB"'
echo -n "device A after    : "; act ',"device_id":"AAA"'
echo -n "old cron traffic  : "; curl -s -X POST localhost:17001/internal/traffic -H 'X-Internal: I' -d '{"port":56001,"bytes":5}'; echo
kill $AP; rm -rf "$D"
