"""Тесты vkturn_client.py: bundle roundtrip, курсоры без потерь/дублей, кластер, пин.

Фейковая нода — локальный HTTPS-сервер (ThreadingHTTPServer в отдельном потоке)
на self-signed сертификате, сгенерированном openssl на лету в tmp_path.
Пин сервера вычисляется библиотечной функцией spki_pin(cert_der).
Тесты синхронные (asyncio.run) — pytest-asyncio не требуется.
"""
import asyncio
import base64
import json
import os
import ssl
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

import vkturn_client as vc


# --- генерация self-signed сертификата --------------------------------------

def _generate_cert(tmpdir):
    """openssl req -x509 → (cert_pem_path, key_pem_path). Временные файлы в tmpdir."""
    cert = os.path.join(tmpdir, "c.pem")
    key = os.path.join(tmpdir, "k.pem")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", key, "-out", cert, "-days", "1", "-subj", "/CN=test"],
        check=True, capture_output=True)
    return cert, key


# --- фейковая нода -----------------------------------------------------------

class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # тишина в выводе pytest
        pass

    def _send(self, obj, status=200):
        raw = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    # маршруты -----------------------------------------------------------------

    def _create_key(self):
        state = self.server.state
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
        state["last_create_body"] = body
        ext = body.get("external_id", "?")
        if ext not in state["keys"]:
            state["keys"][ext] = "key-" + ext.replace(" ", "_") + f"-{len(state['keys'])}"
        self._send({"key": state["keys"][ext], "expires_at": 0, "duplicate": ext in state["keys"]})

    def _revoke(self, key_id):
        self.server.state["revokes"].append(key_id)
        self._send({"status": "revoked"})

    def _get_key(self, key_id):
        state = self.server.state
        for ext, k in state["keys"].items():
            if k == key_id:
                used = sum(d["bytes"] for d in state["usage_log"] if d["key_id"] == key_id)
                self._send({"id": key_id, "external_id": ext, "bytes_used": used})
                return
        self._send({"error": "not found"}, status=404)

    def _usage(self):
        state = self.server.state
        since = int(self.path.split("since=")[1].split("&")[0])
        state["seen_since"].append(since)
        items = [d for d in state["usage_log"] if d["id"] > since]
        items = items[:1000]
        nxt = items[-1]["id"] if items else since
        self._send({"items": items, "next": nxt})

    def do_POST(self):
        state = self.server.state
        state["requests"] += 1
        if self.path == "/v1/admin/keys/create":
            self._create_key()
        elif self.path.endswith("/revoke"):
            self._revoke(self.path[:-len("/revoke")].rsplit("/", 1)[1])
        else:
            self._send({"error": "not found"}, status=404)

    def do_GET(self):
        state = self.server.state
        state["requests"] += 1
        if self.path.startswith("/v1/admin/keys/"):
            self._get_key(self.path.rsplit("/", 1)[1])
        elif self.path.startswith("/v1/admin/usage"):
            self._usage()
        elif self.path == "/v1/admin/health":
            self._send({"ok": True})
        else:
            self._send({"error": "not found"}, status=404)


class FakeNode:
    """Локальная HTTPS-нода: self-signed cert, маршруты Admin API, счётчики."""

    def __init__(self, tmpdir, name="n"):
        cert, key = _generate_cert(tmpdir)
        with open(cert, "rb") as f:
            cert_der = ssl.PEM_cert_to_DER_cert(f.read().decode())
        self.pin = vc.spki_pin(cert_der)

        httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.port = httpd.server_address[1]
        httpd.state = {
            "keys": {}, "usage_log": [], "next_delta_id": 1,
            "requests": 0, "seen_since": [], "last_create_body": None,
            "revokes": [],
        }
        self.state = httpd.state
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        self._httpd = httpd
        threading.Thread(target=httpd.serve_forever, daemon=True, name=name).start()

    def add_deltas(self, key_id, ext, *sizes):
        for size in sizes:
            self.state["usage_log"].append(
                {"id": self.state["next_delta_id"], "key_id": key_id,
                 "external_id": ext, "bytes": size})
            self.state["next_delta_id"] += 1

    def stop(self):
        self._httpd.shutdown()
        self._httpd.server_close()

    @property
    def api(self):
        return f"127.0.0.1:{self.port}"

    def node(self, name=""):
        return vc.Node(self.api, self.pin, "master-token", name=name)


# --- тесты --------------------------------------------------------------------

def test_make_bundle_roundtrip(tmp_path):
    nodes = [FakeNode(str(tmp_path), name="a"), FakeNode(str(tmp_path), name="b")]
    try:
        pairs = [(nodes[0].node("alpha"), "key-1"),
                 (nodes[1].node("beta"), "key-2")]
        link = vc.make_bundle("order-42", pairs, limit=1000)
        assert link.startswith("vkturn://bundle/")
        raw = base64.urlsafe_b64decode(link[len("vkturn://bundle/"):] + "==")
        obj = json.loads(raw)

        # формат 00d §1.3: v=1, имя, s[].api/pin/key/name, limit только если передан
        assert obj["v"] == 1
        assert obj["n"] == "order-42"
        assert obj["limit"] == 1000
        assert set(obj) == {"v", "n", "s", "limit"}  # нет неизвестных полей
        assert len(obj["s"]) == 2
        for server, (node, key) in zip(obj["s"], pairs):
            assert set(server) == {"api", "pin", "key", "name"}  # без unknown fields
            assert server["api"] == node.api
            assert server["pin"] == node.pin and len(server["pin"]) == 64
            assert server["key"] == key
            assert server["name"]

        # без limit поле не пишется
        link2 = vc.make_bundle("order-43", pairs)
        raw2 = json.loads(base64.urlsafe_b64decode(
            link2[len("vkturn://bundle/"):] + "=="))
        assert "limit" not in raw2
        assert set(raw2) == {"v", "n", "s"}
    finally:
        for n in nodes:
            n.stop()


def test_cursors_no_loss_no_double(tmp_path):
    node = FakeNode(str(tmp_path))
    try:
        n = node.node("solo")
        node.add_deltas("key-x", "order-1", 100, 100, 100)

        cluster = vc.Cluster([n], db_path=str(tmp_path / "c.db"))
        totals = asyncio.run(cluster.usage_all())
        assert totals == {"order-1": 300}
        # сервер получил since=0 (3 записи, next=3) и since=3 (пустая страница — конец),
        # курсор стал 3
        assert node.state["seen_since"] == [0, 3]

        node.add_deltas("key-x", "order-1", 50, 50)
        totals = asyncio.run(cluster.usage_all())
        assert totals == {"order-1": 100}
        # запросы: since=3 получает записи 4,5 (next=5); since=5 — пустая (конец);
        # задваивания нет: записи 1-3 больше не приходят
        assert node.state["seen_since"] == [0, 3, 3, 5]

        # повтор без новых записей — 0, не задваивает
        totals = asyncio.run(cluster.usage_all())
        assert totals == {}
        assert node.state["seen_since"] == [0, 3, 3, 5, 5]

        cluster.close()
    finally:
        node.stop()


def test_three_nodes_sum_and_revoke(tmp_path):
    nodes = [FakeNode(str(tmp_path), name=f"n{i}") for i in range(3)]
    try:
        cluster = vc.Cluster([n.node(f"node{i}") for i, n in enumerate(nodes)],
                             db_path=str(tmp_path / "c.db"))
        res = asyncio.run(cluster.create_everywhere(
            "order-1", bytes_limit=1000, local_limit=1000, expires_days=30))
        assert len(res) == 3
        for api, r in res.items():
            assert "key" in r, r
        # local_limit передан в тело запроса каждой ноде
        for n in nodes:
            body = n.state["last_create_body"]
            assert body["local_limit"] == 1000
            assert body["bytes_limit"] == 1000
            assert body["expires_days"] == 30
            assert body["external_id"] == "order-1"
        # маппинг external_id → key_id в DB кластера (проверим через revoke/bundle)
        link = cluster.bundle("order-1", "order-1")
        obj = json.loads(base64.urlsafe_b64decode(
            link[len("vkturn://bundle/"):] + "=="))
        assert len(obj["s"]) == 3

        # трафик: 500 + 300 + 300 = 1100 >= лимита 1000
        for n, size in zip(nodes, (500, 300, 300)):
            key_id = n.state["keys"]["order-1"]
            n.add_deltas(key_id, "order-1", size)
        totals = asyncio.run(cluster.usage_all())
        assert totals == {"order-1": 1100}

        if totals.get("order-1", 0) >= 1000:
            revoked = asyncio.run(cluster.revoke_everywhere("order-1"))
        assert len(revoked) == 3
        for api, r in revoked.items():
            assert r == {"ok": True}, r
        for n in nodes:
            assert n.state["revokes"] == [n.state["keys"]["order-1"]]

        cluster.close()
    finally:
        for n in nodes:
            n.stop()


def test_wrong_pin_request_not_sent(tmp_path):
    node = FakeNode(str(tmp_path))
    try:
        wrong = "ab" * 32  # валидный hex64, но не пин сервера
        assert wrong != node.pin
        n = vc.Node(node.api, wrong, "master-token", name="bad")
        with pytest.raises(vc.PinMismatchError) as ei:
            asyncio.run(n.health())
        assert ei.value.actual == node.pin
        assert ei.value.expected == wrong
        # ни одного байта HTTP: сервер не видел ни одного запроса
        assert node.state["requests"] == 0

        # кривой пин (не hex64) — ValueError при конструировании
        with pytest.raises(ValueError):
            vc.Node(node.api, "not-hex-pin", "master-token")
        with pytest.raises(ValueError):
            vc.Node(node.api, "ab" * 31, "master-token")  # 62 символа
        assert node.state["requests"] == 0
    finally:
        node.stop()
