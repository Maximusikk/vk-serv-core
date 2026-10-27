"""Тонкий async-клиент Admin API VKTurn (контракт: docs/API.md).

API работает только по HTTPS с самоподписанным сертификатом. Доверие строится не на CA,
а на SPKI-пине: SHA-256 от DER SubjectPublicKeyInfo сертификата сервера, строчный hex
(64 символа; `VKTURN_ADMIN_PIN=` из вывода install.sh, `TLS_PIN=` в /opt/vkturn/config.txt).

Порядок на каждом запросе: TCP → TLS-рукопожатие → сверка пина листового сертификата →
только потом HTTP-запрос с X-Admin-Token. Пин не совпал — соединение закрывается,
ни одного байта HTTP (и токена) не отправлено. Режима «без проверки» нет.

Зависимостей сверх стандартной библиотеки нет: SPKI вынимается из DER сертификата
минимальным ASN.1-разбором. Блокирующий http.client вызывается через asyncio.to_thread,
поэтому публичные методы остаются async, как раньше.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import http.client
import json as _json
import os
import re
import socket
import ssl
from urllib.parse import urlencode, urlsplit

GB = 1024 ** 3

_PIN_RE = re.compile(r"^[0-9a-f]{64}$")


class VKTurnError(Exception):
    """Ошибка API. status=0 — сервер недоступен / таймаут / сбой TLS."""

    def __init__(self, status: int, message: str):
        super().__init__(f"{status}: {message}")
        self.status = status
        self.message = message


class PinMismatchError(VKTurnError):
    """Сертификат сервера не совпал с пином. Запрос (и токен) НЕ отправлялись."""

    def __init__(self, expected: str, actual: str):
        super().__init__(0, "TLS pin mismatch")
        self.expected = expected
        self.actual = actual


def parse_pin(value: str) -> str:
    """Нормализует пин: строчный hex 64 символа. Допускает ':' и пробелы, любой регистр."""
    pin = re.sub(r"[\s:]", "", value or "").lower()
    if not _PIN_RE.match(pin):
        raise ValueError(
            "VKTURN_ADMIN_PIN должен быть SHA-256 SPKI-пином: 64 hex-символа "
            "(строка VKTURN_ADMIN_PIN= из вывода install.sh или TLS_PIN= из /opt/vkturn/config.txt)"
        )
    return pin


# --- минимальный DER-разбор: Certificate → tbsCertificate → subjectPublicKeyInfo ----------

def _der_tlv(buf: bytes, pos: int) -> tuple[int, int, int]:
    """Читает TLV на позиции pos. Возвращает (tag, начало значения, конец TLV)."""
    if pos + 2 > len(buf):
        raise ValueError("DER: обрезано")
    tag = buf[pos]
    if tag & 0x1F == 0x1F:
        raise ValueError("DER: многобайтовые теги не поддерживаются")
    ln = buf[pos + 1]
    p = pos + 2
    if ln & 0x80:
        n = ln & 0x7F
        if n == 0 or n > 4 or p + n > len(buf):
            raise ValueError("DER: неверная длина")
        ln = int.from_bytes(buf[p:p + n], "big")
        p += n
    end = p + ln
    if end > len(buf):
        raise ValueError("DER: длина за пределами буфера")
    return tag, p, end


def spki_der(cert_der: bytes) -> bytes:
    """DER SubjectPublicKeyInfo (весь TLV) из DER X.509-сертификата."""
    tag, p, _ = _der_tlv(cert_der, 0)              # Certificate ::= SEQUENCE
    if tag != 0x30:
        raise ValueError("DER: Certificate не SEQUENCE")
    tag, p, _ = _der_tlv(cert_der, p)              # tbsCertificate ::= SEQUENCE
    if tag != 0x30:
        raise ValueError("DER: tbsCertificate не SEQUENCE")
    tag, _, end = _der_tlv(cert_der, p)
    if tag == 0xA0:                                # [0] EXPLICIT version (необязателен)
        p = end
    # serialNumber, signature, issuer, validity, subject
    for want in (0x02, 0x30, 0x30, 0x30, 0x30):
        tag, _, end = _der_tlv(cert_der, p)
        if tag != want:
            raise ValueError("DER: неожиданная структура tbsCertificate")
        p = end
    tag, _, end = _der_tlv(cert_der, p)            # subjectPublicKeyInfo ::= SEQUENCE
    if tag != 0x30:
        raise ValueError("DER: subjectPublicKeyInfo не SEQUENCE")
    return cert_der[p:end]


def spki_pin(cert_der: bytes) -> str:
    """Пин сертификата: SHA-256 от DER SPKI, строчный hex (как spkiPin в api/tls.go)."""
    return hashlib.sha256(spki_der(cert_der)).hexdigest()


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS-соединение, которое сверяет SPKI-пин сразу после рукопожатия, до любого HTTP.

    CA и имя хоста не проверяются (сертификат самоподписанный, адрес — IP) — это допустимо
    ТОЛЬКО потому, что листовой сертификат обязательно сверяется с пином. Без пина класс
    не создаётся.
    """

    def __init__(self, host: str, port: int, *, pin: str, timeout: float):
        if not pin or not _PIN_RE.match(pin):
            raise ValueError("pinned connection requires a valid pin")
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.check_hostname = False          # заменено проверкой пина ниже
        ctx.verify_mode = ssl.CERT_NONE     # заменено проверкой пина ниже
        super().__init__(host, port, timeout=timeout, context=ctx)
        self._pin = pin
        self._ctx = ctx

    def connect(self) -> None:
        raw = socket.create_connection((self.host, self.port), self.timeout, self.source_address)
        try:
            tls = self._ctx.wrap_socket(raw, server_hostname=None)  # рукопожатие здесь
        except BaseException:
            raw.close()
            raise
        try:
            der = tls.getpeercert(binary_form=True)
            if not der:
                raise ssl.SSLError("server sent no certificate")
            actual = spki_pin(der)
        except BaseException:
            tls.close()
            raise
        if not hmac.compare_digest(actual, self._pin):
            tls.close()
            raise PinMismatchError(self._pin, actual)
        self.sock = tls


class VKTurnClient:
    def __init__(self, base_url: str, admin_token: str, timeout: float = 10.0, *,
                 pin: str | None = None):
        """base_url — `https://IP:7000` (без схемы — подставится https://; http:// не принимается).
        pin — SPKI-пин сервера; если не передан, берётся из VKTURN_ADMIN_PIN. Без пина — ValueError.
        """
        if pin is None:
            pin = os.environ.get("VKTURN_ADMIN_PIN", "")
        self._pin = parse_pin(pin)

        url = base_url.strip()
        if "://" not in url:
            url = "https://" + url
        parts = urlsplit(url)
        if parts.scheme.lower() != "https":
            raise ValueError("VKTURN_API_URL должен быть https:// — API работает только по HTTPS")
        if not parts.hostname:
            raise ValueError("VKTURN_API_URL: не указан хост")
        self._host = parts.hostname
        self._port = parts.port or 7000
        # Новым ботам рекомендован префикс /v1 (см. docs/API.md).
        self._prefix = parts.path.rstrip("/") + "/v1"
        self._token = admin_token
        self._timeout = timeout

    async def close(self) -> None:
        """Совместимость: соединения не переиспользуются, закрывать нечего."""
        return None

    def _do(self, method: str, path: str, body: bytes | None) -> tuple[int, str, bytes]:
        conn = _PinnedHTTPSConnection(self._host, self._port, pin=self._pin, timeout=self._timeout)
        try:
            conn.connect()  # TLS + пин; токен ещё не отправлен
            headers = {"X-Admin-Token": self._token, "Accept": "application/json"}
            if body is not None:
                headers["Content-Type"] = "application/json"
            conn.request(method, path, body=body, headers=headers)
            resp = conn.getresponse()
            return resp.status, resp.reason, resp.read(1 << 20)
        finally:
            conn.close()

    async def _request(self, method: str, path: str, *, json: dict | None = None,
                       params: dict | None = None) -> dict:
        full = self._prefix + path
        if params:
            full += "?" + urlencode(params)
        body = _json.dumps(json).encode() if json is not None else None
        try:
            status, reason, raw = await asyncio.to_thread(self._do, method, full, body)
        except PinMismatchError:
            raise
        except (socket.timeout, TimeoutError) as e:
            raise VKTurnError(0, "timeout") from e
        except ssl.SSLError as e:
            raise VKTurnError(0, "TLS error") from e
        except (OSError, http.client.HTTPException) as e:
            raise VKTurnError(0, "server unreachable") from e
        try:
            data = _json.loads(raw) if raw else None
        except ValueError:
            data = None
        if status >= 400:
            msg = data.get("error") if isinstance(data, dict) else None
            raise VKTurnError(status, msg or reason or "error")
        return data if isinstance(data, dict) else {}

    # --- ключи -----------------------------------------------------------------

    async def create_key(self, *, external_id: str, days: int, bytes_limit: int = 0,
                         notes: str = "") -> dict:
        """Идемпотентно по external_id (номер заказа): повтор вернёт тот же ключ, duplicate=true.

        Срок идёт с ПЕРВОЙ АКТИВАЦИИ (C5, start=on_activation): ключ, выданный в понедельник
        и запущенный в пятницу, не теряет четыре дня.
        Поле link в ответе уже содержит ?pin=<hex> — отдавайте его покупателю как есть.
        """
        body = {
            "expires_days": days,
            "start": "on_activation",
            "bytes_limit": bytes_limit,  # 0 = безлимит
            "external_id": external_id,
        }
        if notes:
            body["notes"] = notes
        return await self._request("POST", "/admin/keys/create", json=body)

    async def get_key(self, key_id: str) -> dict:
        return await self._request("GET", f"/admin/keys/{key_id}")

    async def extend(self, key_id: str, days: int) -> dict:
        """Продление. У погашенного ключа сервер сам поднимает порт (в ответе new_port)."""
        return await self._request("PATCH", f"/admin/keys/{key_id}", json={"expires_days": days})

    async def add_traffic(self, key_id: str, nbytes: int) -> dict:
        return await self._request("POST", f"/admin/keys/{key_id}/add_traffic",
                                   json={"bytes": nbytes})

    async def unbind(self, key_id: str) -> dict:
        """Снять привязку к устройству. Не чаще раза в 7 дней на ключ (иначе 429)."""
        return await self._request("POST", f"/admin/keys/{key_id}/unbind")

    async def revoke(self, key_id: str) -> dict:
        return await self._request("POST", f"/admin/keys/{key_id}/revoke")

# --- Этап 2A/2C: нода, кластер, bundle-ссылка -----------------------------------------------

import base64 as _b64
import logging as _logging
import sqlite3 as _sqlite3

_log = _logging.getLogger("vkturn_client")


class Node:
    """Одна нода VKTurn под управлением бота-мастера (авторизация master-token, этап 2A).

    api   — host:port API (например "203.0.113.10:7000"; "https://" дописывается, http запрещён);
    pin   — SPKI-пин сертификата ноды (VKTURN_ADMIN_PIN/VKTURN_MASTER_PIN из вывода install.sh);
    token — MASTER_TOKEN ноды (VKTURN_MASTER_TOKEN из вывода install.sh/upgrade.sh).

    TLS-пин проверяется до отправки токена — наследует механику VKTurnClient.
    """

    def __init__(self, api: str, pin: str, token: str, *, name: str = "", timeout: float = 10.0):
        self.name = name or api
        url = api.strip()
        if "://" not in url:
            url = "https://" + url
        parts = urlsplit(url)
        if parts.scheme.lower() != "https":
            raise ValueError("Node.api должен быть host:port (https подразумевается)")
        if not parts.hostname:
            raise ValueError("Node.api: не указан хост")
        self.api = f"{parts.hostname}:{parts.port or 7000}"
        self.pin = parse_pin(pin)
        self._client = VKTurnClient(url, token, timeout, pin=self.pin)

    async def create_key(self, *, external_id: str, bytes_limit: int = 0,
                         local_limit: int = 0, expires_days: int = 0) -> dict:
        """Создать ключ (этап 2A). local_limit — локальный стоп-кран ноды на случай
        пропажи мастера. Идемпотентно по external_id."""
        body: dict = {
            "expires_days": expires_days,
            "start": "on_activation",
            "bytes_limit": bytes_limit,
            "external_id": external_id,
        }
        if local_limit:
            body["local_limit"] = local_limit
        return await self._client._request("POST", "/admin/keys/create", json=body)

    async def revoke(self, key_id: str) -> dict:
        return await self._client.revoke(key_id)

    async def get_key(self, key_id: str) -> dict:
        return await self._client.get_key(key_id)

    async def usage(self, since: int = 0, limit: int = 1000) -> dict:
        """Дельты трафика по курсору (2A): {"items": [{key_id, external_id, bytes}], "next": <id>}."""
        return await self._client._request("GET", "/admin/usage",
                                           params={"since": since, "limit": limit})

    async def health(self) -> dict:
        return await self._client._request("GET", "/admin/health")


def make_bundle(name: str, pairs, limit: int | None = None) -> str:
    """Собирает vkturn://bundle/… (формат: _review/00d_protocol_map.md §1.3).

    pairs — [(Node, key_id), ...]. Неизвестных полей не добавляем (этап 3 расширит).
    """
    servers = [{"api": node.api, "pin": node.pin, "key": key,
                "name": getattr(node, "name", "") or node.api}
               for node, key in pairs]
    obj: dict = {"v": 1, "n": name, "s": servers}
    if limit is not None:
        obj["limit"] = int(limit)
    raw = _json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return "vkturn://bundle/" + _b64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


class Cluster:
    """Мастер поверх нескольких нод: ключи с одним external_id на всех, сбор дельт
    по курсорам (курсоры и соответствие external_id→key_id в SQLite), отзыв везде.
    Курсор ноды двигается только после полного успешного забора — при сбое нода
    отдаст те же записи снова, дельты не теряются и не задваиваются."""

    def __init__(self, nodes: list[Node], db_path: str = "cluster.db"):
        self.nodes = nodes
        self._db = _sqlite3.connect(db_path, check_same_thread=False)
        self._db.executescript("""
            CREATE TABLE IF NOT EXISTS cursors (
                node  TEXT PRIMARY KEY,   -- api ноды
                since INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS keys (
                external_id TEXT NOT NULL,
                node        TEXT NOT NULL,
                key_id      TEXT NOT NULL,
                bytes_limit INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (external_id, node)
            );
        """)
        self._db.commit()

    def close(self) -> None:
        self._db.close()

    # -- внутреннее ------------------------------------------------------------------

    def _cursor(self, api: str) -> int:
        row = self._db.execute("SELECT since FROM cursors WHERE node = ?", (api,)).fetchone()
        return int(row[0]) if row else 0

    def _set_cursor(self, api: str, since: int) -> None:
        self._db.execute(
            "INSERT INTO cursors (node, since) VALUES (?, ?) "
            "ON CONFLICT(node) DO UPDATE SET since = excluded.since", (api, since))
        self._db.commit()

    # -- операции --------------------------------------------------------------------

    async def create_everywhere(self, external_id: str, *, bytes_limit: int = 0,
                                local_limit: int = 0, expires_days: int = 0) -> dict:
        """Один external_id на все ноды. {api: {"key": id}} для удачных,
        {api: {"error": msg}} для неудач (частичный успех допустим)."""
        out: dict = {}
        for node in self.nodes:
            try:
                resp = await node.create_key(
                    external_id=external_id, bytes_limit=bytes_limit,
                    local_limit=local_limit, expires_days=expires_days)
                key_id = resp["key"]
                out[node.api] = {"key": key_id}
                self._db.execute(
                    "INSERT INTO keys (external_id, node, key_id, bytes_limit) VALUES (?, ?, ?, ?) "
                    "ON CONFLICT(external_id, node) DO UPDATE SET key_id = excluded.key_id, "
                    "bytes_limit = excluded.bytes_limit",
                    (external_id, node.api, key_id, bytes_limit))
                self._db.commit()
            except Exception as e:
                out[node.api] = {"error": str(e)}
        return out

    async def usage_all(self) -> dict[str, int]:
        """Забирает дельты со всех нод по их курсорам; возвращает СУММУ прироста байт
        по каждому external_id. Курсор двигается только при полном успехе забора ноды."""
        totals: dict[str, int] = {}
        for node in self.nodes:
            since = self._cursor(node.api)
            try:
                while True:
                    page = await node.usage(since=since, limit=1000)
                    for item in page.get("items", []):
                        ext = item.get("external_id") or item.get("key_id")
                        totals[ext] = totals.get(ext, 0) + int(item.get("bytes", 0))
                    nxt = int(page.get("next", since))
                    if not page.get("items") or nxt <= since:
                        since = nxt
                        break
                    since = nxt
                self._set_cursor(node.api, since)
            except Exception as e:
                _log.warning("usage_all: нода %s: %s", node.api, e)
        return totals

    async def revoke_everywhere(self, external_id: str) -> dict:
        """Отозвать ключ external_id на всех нодах, где он есть. {api: {"ok": true}|{"error": msg}}."""
        rows = self._db.execute(
            "SELECT node, key_id FROM keys WHERE external_id = ?", (external_id,)).fetchall()
        out: dict = {}
        for api, key_id in rows:
            node = next((n for n in self.nodes if n.api == api), None)
            if node is None:
                out[api] = {"error": "нода не подключена к кластеру"}
                continue
            try:
                await node.revoke(key_id)
                out[api] = {"ok": True}
            except Exception as e:
                out[api] = {"error": str(e)}
        return out

    def bundle(self, external_id: str, name: str) -> str:
        """Собирает bundle-ссылку из созданных ключей. KeyError, если ключей нет нигде."""
        rows = self._db.execute(
            "SELECT node, key_id FROM keys WHERE external_id = ?", (external_id,)).fetchall()
        by_api = {r[0]: r[1] for r in rows}
        pairs = [(n, by_api[n.api]) for n in self.nodes if n.api in by_api]
        if not pairs:
            raise KeyError(f"нет созданных ключей для {external_id!r}")
        return make_bundle(name, pairs)
