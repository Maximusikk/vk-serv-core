"""Референс-бот продавца VKTurn в кластерном режиме (Python 3.10+, aiogram 3).

Бот-мастер поверх нескольких нод VKTurn (этап 2C). Команды: /buy, /status.
Это ПРИМЕР: оплаты здесь нет. Функция may_purchase() — место, куда продавец подключает
свою проверку оплаты. Покупать (/buy) могут только ADMIN_IDS.

Настройка — переменными окружения (см. README.md). Токены в логи не пишутся.

Как работает:
  /buy <order_id> [дней] [ГБ]
      → Cluster.create_everywhere(): ключ с одним external_id создаётся на ВСЕХ нодах,
        локальный стоп-кран (local_limit) на каждой ноде = общий лимит — страховка,
        если бот упадёт и перестанет отзывать ключи;
      → хотя бы одна нода удалась → Cluster.bundle(): юзеру отправляется
        vkturn://bundle-ссылка на все серверы сразу;
      → частичный успех: ноды с ошибками перечисляются админу;
      → ни одна не удалась — сообщение об ошибке.
  Фоновая задача (раз в 60 с):
      → Cluster.usage_all(): дельты трафика со всех нод по курсорам;
      → дельты суммируются в локальной SQLite бота (таблица usage);
      → used >= limit → Cluster.revoke_everywhere() + пометка revoked_at,
        уведомление админам «Лимит исчерпан, подписка отозвана везде».
  /status [order] — для админов: сколько нод ответили, used/limit по каждому order,
      отозван или нет.
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
import sqlite3
import time

from aiogram import Bot, Dispatcher, Router
from aiogram.filters import Command, CommandObject
from aiogram.types import Message

from vkturn_client import GB, Cluster, Node, VKTurnError, parse_pin

log = logging.getLogger("seller_bot")

ORDER_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
MAX_DAYS = 3650
MAX_GB = 100_000
USAGE_INTERVAL = 60  # сек между заборами дельт

HELP = (
    "Команды (кластерный режим):\n"
    "/buy <order_id> [дней] [ГБ] — подписка на все серверы (ГБ=0 — безлимит)\n"
    "/status [order] — состояние подписок: ноды, used/limit, отозван ли\n"
    "\n"
    "Оплата подключается в may_purchase() в bot.py."
)


class Config:
    def __init__(self) -> None:
        self.bot_token = os.environ["BOT_TOKEN"]
        self.admin_ids = {int(x) for x in os.environ.get("ADMIN_IDS", "").replace(" ", "").split(",") if x}
        self.default_days = int(os.environ.get("DEFAULT_DAYS", "30"))
        self.default_gb = int(os.environ.get("DEFAULT_GB", "10"))
        self.db_path = os.environ.get("DB_PATH", "seller_bot.db")
        # NODES: список нод через ';', каждая — host:port|pin|MASTER_TOKEN|имя (имя опционально)
        self.nodes = self._parse_nodes(os.environ.get("NODES", ""))

    @staticmethod
    def _parse_nodes(spec: str) -> list[Node]:
        nodes: list[Node] = []
        for i, chunk in enumerate([c for c in spec.split(";") if c.strip()], 1):
            parts = [p.strip() for p in chunk.split("|")]
            if len(parts) not in (3, 4):
                raise ValueError(
                    f"NODES: нода #{i} — ожидается host:port|pin|MASTER_TOKEN|имя "
                    f"(имя опционально), получено {len(parts)} полей")
            api, pin, token = parts[0], parts[1], parts[2]
            name = parts[3] if len(parts) == 4 else ""
            try:
                nodes.append(Node(api, parse_pin(pin), token, name=name))
            except ValueError as e:
                raise ValueError(f"NODES: нода #{i} ({name or api}): {e}") from e
        return nodes


class Store:
    """Локальная база бота: заказы и суммарный трафик по ним (дельты нод складываются здесь)."""

    def __init__(self, path: str) -> None:
        self.db = sqlite3.connect(path)
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS orders(
                 order_id     TEXT PRIMARY KEY,
                 name         TEXT NOT NULL DEFAULT '',
                 limit_bytes  INTEGER NOT NULL,
                 expires_days INTEGER NOT NULL,
                 created_at   INTEGER NOT NULL,
                 revoked_at   INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS usage(
                 order_id TEXT PRIMARY KEY,
                 used     INTEGER NOT NULL DEFAULT 0);
        """)
        self.db.commit()

    def add_order(self, order_id: str, name: str, limit_bytes: int, expires_days: int) -> None:
        self.db.execute(
            "INSERT OR IGNORE INTO orders(order_id, name, limit_bytes, expires_days, created_at) "
            "VALUES (?,?,?,?,?)", (order_id, name, limit_bytes, expires_days, int(time.time())))
        self.db.execute("INSERT OR IGNORE INTO usage(order_id, used) VALUES (?, 0)", (order_id,))
        self.db.commit()

    def add_used(self, order_id: str, nbytes: int) -> int:
        self.db.execute("UPDATE usage SET used = used + ? WHERE order_id = ?", (nbytes, order_id))
        self.db.commit()
        return self.used(order_id)

    def used(self, order_id: str) -> int:
        row = self.db.execute("SELECT used FROM usage WHERE order_id = ?", (order_id,)).fetchone()
        return int(row[0]) if row else 0

    def order(self, order_id: str) -> dict | None:
        row = self.db.execute(
            "SELECT order_id, name, limit_bytes, expires_days, created_at, revoked_at "
            "FROM orders WHERE order_id = ?", (order_id,)).fetchone()
        if not row:
            return None
        return dict(zip(("order_id", "name", "limit_bytes", "expires_days",
                         "created_at", "revoked_at"), row))

    def orders(self) -> list[dict]:
        rows = self.db.execute(
            "SELECT order_id, name, limit_bytes, expires_days, created_at, revoked_at "
            "FROM orders ORDER BY created_at DESC").fetchall()
        return [dict(zip(("order_id", "name", "limit_bytes", "expires_days",
                          "created_at", "revoked_at"), r)) for r in rows]

    def mark_revoked(self, order_id: str) -> None:
        self.db.execute("UPDATE orders SET revoked_at = ? WHERE order_id = ?",
                        (int(time.time()), order_id))
        self.db.commit()


def fmt_bytes(n: int) -> str:
    v = float(n)
    for unit in ("Б", "КБ", "МБ", "ГБ"):
        if v < 1024:
            return f"{v:.0f} {unit}" if unit == "Б" else f"{v:.1f} {unit}"
        v /= 1024
    return f"{v:.1f} ТБ"


def to_int(s: str, lo: int, hi: int) -> int | None:
    try:
        v = int(s)
    except ValueError:
        return None
    return v if lo <= v <= hi else None


def build_router(cfg: Config, cluster: Cluster, store: Store, bot: Bot) -> Router:
    r = Router()

    def is_admin(uid: int) -> bool:
        return uid in cfg.admin_ids

    def may_purchase(uid: int) -> bool:
        """ПОДКЛЮЧИТЕ ОПЛАТУ ЗДЕСЬ: вернуть True, только если пользователь реально оплатил."""
        return is_admin(uid)

    async def notify_admins(text: str) -> None:
        for uid in cfg.admin_ids:
            try:
                await bot.send_message(uid, text)
            except Exception as e:  # телеграм может недоступен — не падаем
                log.warning("notify_admins(%s): %s", uid, e)

    @r.message(Command("start", "help"))
    async def cmd_help(m: Message) -> None:
        await m.answer(HELP)

    @r.message(Command("buy"))
    async def cmd_buy(m: Message, command: CommandObject) -> None:
        uid = m.from_user.id
        if not may_purchase(uid):
            await m.answer("Оплата ещё не подтверждена. Обратитесь к продавцу.")
            return
        parts = (command.args or "").split()
        usage = "Использование: /buy <order_id> [дней] [ГБ]  (ГБ=0 — безлимит)"
        if not parts or not ORDER_RE.match(parts[0]):
            await m.answer(usage)
            return
        order_id = parts[0]
        days = to_int(parts[1], 1, MAX_DAYS) if len(parts) > 1 else cfg.default_days
        gb = to_int(parts[2], 0, MAX_GB) if len(parts) > 2 else cfg.default_gb
        if days is None or gb is None:
            await m.answer(usage)
            return
        limit_bytes = gb * GB
        old = store.order(order_id)
        if old and old["revoked_at"]:
            await m.answer("Этот заказ уже отозван. Используйте новый order_id.")
            return
        # Один external_id на все ноды; local_limit = общий лимит — стоп-кран ноды на случай
        # пропажи мастера (бот упал — нода сама остановит трафик).
        res = await cluster.create_everywhere(order_id, bytes_limit=limit_bytes,
                                              local_limit=limit_bytes, expires_days=days)
        ok = {api: r for api, r in res.items() if "key" in r}
        failed = {api: r["error"] for api, r in res.items() if "error" in r}
        if not ok:
            await m.answer("Не удалось создать подписку ни на одной ноде: "
                           + "; ".join(f"{api}: {err}" for api, err in failed.items()))
            return
        # Частичный успех: создаём то, что есть, добираем при следующем /buy с тем же order
        # (идемпотентно). Store дополняем актуальными значениями.
        name = old["name"] if old else order_id
        store.add_order(order_id, name, limit_bytes, days)
        try:
            link = cluster.bundle(order_id, name)
        except KeyError:
            await m.answer("Внутренняя ошибка: ключи созданы, но bundle не собрался. См. лог.")
            return
        if failed:
            await notify_admins(
                f"/buy {order_id}: частичный успех, ноды с ошибками:\n"
                + "\n".join(f"• {api}: {err}" for api, err in failed.items()))
        lines = ["Ссылка для приложения (вставьте целиком):",
                 f"`{link}`",
                 f"Подписка «{name}»: серверов {len(ok)}/{len(cluster.nodes)}, "
                 f"лимит {fmt_bytes(limit_bytes)}, срок {days} дн. (с первой активации)."]
        await m.answer("\n".join(lines), parse_mode="Markdown")

    @r.message(Command("status"))
    async def cmd_status(m: Message, command: CommandObject) -> None:
        if not is_admin(m.from_user.id):
            await m.answer("Только для админов.")
            return
        arg = (command.args or "").split()
        orders = [o for o in store.orders() if not arg or o["order_id"] == arg[0]]
        if not orders:
            await m.answer("Заказы не найдены.")
            return
        # Сколько нод сейчас отвечают (health-проверка, не считается ошибкой бота).
        alive = 0
        for node in cluster.nodes:
            try:
                await node.health()
                alive += 1
            except Exception as e:
                log.warning("health %s: %s", node.api, e)
        lines = [f"Нод в кластере: {len(cluster.nodes)}, отвечают: {alive}."]
        for o in orders:
            used = store.used(o["order_id"])
            limit = o["limit_bytes"]
            st = ", отозван" if o["revoked_at"] else ""
            lines.append(f"• {o['order_id']} «{o['name']}»: "
                         f"{fmt_bytes(used)} / " + ("безлимит" if not limit else fmt_bytes(limit))
                         + f", срок {o['expires_days']} дн.{st}")
        await m.answer("\n".join(lines))

    return r


async def usage_loop(cfg: Config, cluster: Cluster, store: Store, bot: Bot) -> None:
    """Каждые USAGE_INTERVAL сек забирает дельты со всех нод и складывает в локальную БД.
    При исчерпании лимита — revoke_everywhere + пометка + уведомление админам."""
    log.info("usage loop: интервал %s с", USAGE_INTERVAL)
    while True:
        await asyncio.sleep(USAGE_INTERVAL)
        try:
            totals = await cluster.usage_all()
        except Exception as e:  # задача не должна умирать
            log.warning("usage_all: %s", e)
            continue
        for order_id, delta in totals.items():
            if delta <= 0 or not order_id:
                continue
            try:
                used = store.add_used(order_id, delta)
                o = store.order(order_id)
                if o is None or o["revoked_at"]:
                    continue
                limit = o["limit_bytes"]
                log.info("usage %s: +%s, всего %s / %s", order_id, fmt_bytes(delta),
                         fmt_bytes(used), fmt_bytes(limit) if limit else "безлимит")
                if limit and used >= limit:
                    log.warning("order %s: лимит исчерпан, отзываю везде", order_id)
                    res = await cluster.revoke_everywhere(order_id)
                    store.mark_revoked(order_id)
                    errs = [f"{api}: {r['error']}" for api, r in res.items() if "error" in r]
                    msg = f"Лимит исчерпан, подписка «{o['name'] or order_id}» отозвана везде."
                    if errs:
                        msg += "\nОшибки отзыва:\n" + "\n".join(f"• {e}" for e in errs)
                    await _notify(cfg, bot, msg)
            except Exception as e:
                log.warning("usage apply %s: %s", order_id, e)


async def _notify(cfg: Config, bot: Bot, text: str) -> None:
    for uid in cfg.admin_ids:
        try:
            await bot.send_message(uid, text)
        except Exception as e:
            log.warning("notify(%s): %s", uid, e)


async def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    # Токены и пины в лог не попадают: Node/Cluster их не логируют, здесь тоже не печатаем.
    try:
        cfg = Config()
    except KeyError as e:
        raise SystemExit(f"Не задана переменная окружения {e.args[0]} (см. README.md)")
    except ValueError as e:
        raise SystemExit(f"Неверная настройка: {e}")
    if not cfg.nodes:
        raise SystemExit("NODES не задан или пуст — кластерный боту нечего обслуживать (см. README.md)")
    log.info("нод в кластере: %d", len(cfg.nodes))
    cluster = Cluster(cfg.nodes, db_path=cfg.db_path)
    store = Store(cfg.db_path)
    bot = Bot(cfg.bot_token)
    dp = Dispatcher()
    dp.include_router(build_router(cfg, cluster, store, bot))
    task = asyncio.create_task(usage_loop(cfg, cluster, store, bot))
    try:
        await dp.start_polling(bot)
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        await bot.session.close()
        cluster.close()


if __name__ == "__main__":
    asyncio.run(main())
