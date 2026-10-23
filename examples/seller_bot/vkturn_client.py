"""Тонкий async-клиент Admin API VKTurn (контракт: docs/API.md)."""
from __future__ import annotations

import asyncio

import aiohttp

GB = 1024 ** 3


class VKTurnError(Exception):
    """Ошибка API. status=0 — сервер недоступен / таймаут."""

    def __init__(self, status: int, message: str):
        super().__init__(f"{status}: {message}")
        self.status = status
        self.message = message


class VKTurnClient:
    def __init__(self, base_url: str, admin_token: str, timeout: float = 10.0):
        # Новым ботам рекомендован префикс /v1 (см. docs/API.md).
        self._base = base_url.rstrip("/") + "/v1"
        self._headers = {"X-Admin-Token": admin_token}
        self._timeout = aiohttp.ClientTimeout(total=timeout)
        self._session: aiohttp.ClientSession | None = None

    async def close(self) -> None:
        if self._session is not None and not self._session.closed:
            await self._session.close()

    async def _request(self, method: str, path: str, *, json: dict | None = None,
                       params: dict | None = None) -> dict:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(headers=self._headers, timeout=self._timeout)
        try:
            async with self._session.request(method, self._base + path, json=json,
                                             params=params) as resp:
                try:
                    data = await resp.json(content_type=None)
                except ValueError:
                    data = None
                if resp.status >= 400:
                    msg = data.get("error") if isinstance(data, dict) else None
                    raise VKTurnError(resp.status, msg or resp.reason or "error")
                return data if isinstance(data, dict) else {}
        except asyncio.TimeoutError as e:
            raise VKTurnError(0, "timeout") from e
        except aiohttp.ClientError as e:
            raise VKTurnError(0, "server unreachable") from e

    # --- ключи -----------------------------------------------------------------

    async def create_key(self, *, external_id: str, days: int, bytes_limit: int = 0,
                         notes: str = "") -> dict:
        """Идемпотентно по external_id (номер заказа): повтор вернёт тот же ключ, duplicate=true.

        Срок идёт с ПЕРВОЙ АКТИВАЦИИ (C5, start=on_activation): ключ, выданный в понедельник
        и запущенный в пятницу, не теряет четыре дня.
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
