#!/bin/bash
# go vet + unit-тесты API и сервера + проверка install.sh
export GOROOT=$HOME/go GOPATH=$HOME/gopath GOCACHE=$HOME/.cache/go-build
export PATH=$GOROOT/bin:$GOPATH/bin:$PATH
cd /mnt/c/Core
echo "== api vet/test"; go vet -C ./api . && go test -C ./api -count=1 -v ./... 2>&1 | grep -E "^(--- |ok|FAIL|PASS)|Fatal|расход"
echo "== server vet"; go vet ./server && echo ok
echo "== install.sh"; bash -n install.sh && echo "syntax ok"
grep -c "Проверка системы" install.sh
# Реальный рендер heredoc через bash
INSTALL_DIR=/opt/vkturn HY2_PORT=10443 bash -c "$(sed -n '/vkserv@.service << TMPLEOF/,/^TMPLEOF$/p' install.sh | sed 's#/etc/systemd/system/vkserv@.service#/dev/stdout#')" | grep ExecStart
