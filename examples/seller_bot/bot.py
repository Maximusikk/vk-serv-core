"""Референс-бот продавца VKTurn (Python 3.10+, aiogram 3).

Команды: /buy, /status, /traffic, /extend, /addtraffic, /unbind.
Это ПРИМЕР: оплаты здесь нет. Функция may_purchase() — место, куда продавец подключает
свою проверку оплаты. По умолчанию покупать (/buy, /extend, /addtraffic) могут только ADMIN_IDS.

Настройка — переменными окружения (см. README.md). Токены в логи не пишутся.
API — только HTTPS с проверкой SPKI-пина (VKTURN_ADMIN_PIN, обязателен): токен уходит на
сервер только после того, как сертификат совпал с пином.
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

from vkturn_client import GB, PinMismatchError, VKTurnClient, VKTurnError, parse_pin

log = logging.getLogger("seller_bot")

KEY_RE = re.compile(r"^[0-9a-fA-F]{4}(-[0-9a-fA-F]{4}){3}$")  # xxxx-xxxx-xxxx-xxxx
ORDER_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
MAX_DAYS = 3650
MAX_GB = 100_000

HELP = (
    "Команды:\n"
    "/status [ключ] — состояние подписки\n"
    "/traffic [ключ] — использованный трафик\n"
    "/unbind [ключ] yes — перенос на другое устройство (раз в 7 дней)\n"
    "\n"
    "Для продавца / после оплаты:\n"
    "/buy <order_id> [дней] [ГБ] — выдать ключ (ГБ=0 — безлимит)\n"
    "/extend [ключ] [дней] — продлить\n"
    "/addtraffic [ключ] <ГБ> — докупить трафик"
)


class Config:
    def __init__(self) -> None:
        self.bot_token = os.environ["BOT_TOKEN"]
        self.api_url = os.environ["VKTURN_API_URL"]
        self.admin_token = os.environ["VKTURN_ADMIN_TOKEN"]
        # SPKI-пин сертификата API (VKTURN_ADMIN_PIN= из вывода install.sh / TLS_PIN= в config.txt).
        # Обязателен: без него бот не стартует (режима «без проверки сертификата» нет).
        self.admin_pin = parse_pin(os.environ["VKTURN_ADMIN_PIN"])
        self.admin_ids = {int(x) for x in os.environ.get("ADMIN_IDS", "").replace(" ", "").split(",") if x}
        self.open_purchases = os.environ.get("OPEN_PURCHASES") == "1"  # только для тестов!
        self.default_days = int(os.environ.get("DEFAULT_DAYS", "30"))
        self.db_path = os.environ.get("DB_PATH", "seller_bot.db")


class Store:
    """Локальная связь «заказ → пользователь Telegram → ключ» (чтобы /status был только у владельца)."""

    def __init__(self, path: str) -> None:
        self.db = sqlite3.connect(path)
        self.db.execute(
            """CREATE TABLE IF NOT EXISTS keys(
                 order_id TEXT PRIMARY KEY,
                 tg_user_id INTEGER NOT NULL,
                 key_id TEXT NOT NULL UNIQUE,
                 created_at INTEGER NOT NULL)"""
        )
        self.db.commit()

    def order_owner(self, order_id: str) -> int | None:
        row = self.db.execute("SELECT tg_user_id FROM keys WHERE order_id = ?", (order_id,)).fetchone()
        return row[0] if row else None

    def add(self, order_id: str, uid: int, key_id: str) -> None:
        self.db.execute(
            "INSERT OR IGNORE INTO keys(order_id, tg_user_id, key_id, created_at) VALUES (?,?,?,?)",
            (order_id, uid, key_id, int(time.time())),
        )
        self.db.commit()

    def keys_of(self, uid: int) -> list[str]:
        rows = self.db.execute(
            "SELECT key_id FROM keys WHERE tg_user_id = ? ORDER BY created_at DESC, rowid DESC", (uid,)
        ).fetchall()
        return [r[0] for r in rows]

    def key_owner(self, key_id: str) -> int | None:
        row = self.db.execute("SELECT tg_user_id FROM keys WHERE key_id = ?", (key_id,)).fetchone()
        return row[0] if row else None


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


def split_args(raw: str | None) -> tuple[str | None, list[str]]:
    """Выделяет необязательный ключ из аргументов команды; остальное — позиционные аргументы."""
    key, rest = None, []
    for tok in (raw or "").split():
        if key is None and KEY_RE.match(tok):
            key = tok.lower()
        else:
            rest.append(tok)
    return key, rest


def explain(e: VKTurnError) -> str:
    if isinstance(e, PinMismatchError):
        # Токен не отправлен. Либо сертификат сервера сменили (rotate-cert.sh --new-key),
        # либо соединение перехвачено. Пин в логе не секрет; токен не пишем.
        log.error("TLS pin mismatch: expected %s, server presented %s", e.expected, e.actual)
        return "Сервер VKTurn сейчас недоступен. Попробуйте позже."
    if e.status == 0:
        return "Сервер VKTurn сейчас недоступен. Попробуйте позже."
    if e.status == 404:
        return "Ключ не найден."
    if e.status == 429:
        return "Слишком часто. Для переноса на другое устройство — не чаще раза в 7 дней."
    if e.status in (401, 403):
        return "Сервер отклонил запрос бота (проверьте VKTURN_ADMIN_TOKEN / -admin-allow)."
    if e.status == 400:
        return f"Некорректный запрос: {e.message}"
    log.warning("API error: %s", e)
    return "Ошибка сервера VKTurn. Попробуйте позже."


def describe(k: dict) -> str:
    lines = [f"Ключ: {k.get('id', '?')}"]
    days_left = k.get("days_left", -1)
    if k.get("revoked_at") or k.get("status") == "revoked":
        lines.append("Статус: отозван продавцом")
    elif not k.get("activated_at"):
        if days_left and days_left > 0:
            lines.append(f"Статус: не активирован. Срок {days_left} дн. начнётся с первой активации.")
        else:
            lines.append("Статус: не активирован (бессрочный).")
    elif k.get("active"):
        lines.append("Статус: активен, " + ("бессрочно" if days_left < 0 else f"осталось {days_left} дн."))
    else:
        lines.append("Статус: истёк срок или исчерпан трафик — продлите или докупите ГБ.")
    used, limit = int(k.get("bytes_used", 0) or 0), int(k.get("bytes_limit", 0) or 0)
    lines.append(f"Трафик: {fmt_bytes(used)} из " + (fmt_bytes(limit) if limit else "безлимита"))
    lines.append("Устройство: " + ("привязано" if k.get("device_bound") else "не привязано"))
    return "\n".join(lines)


def build_router(cfg: Config, api: VKTurnClient, store: Store) -> Router:
    r = Router()

    def is_admin(uid: int) -> bool:
        return uid in cfg.admin_ids

    def may_purchase(uid: int) -> bool:
        """ПОДКЛЮЧИТЕ ОПЛАТУ ЗДЕСЬ: вернуть True, только если пользователь реально оплатил."""
        return cfg.open_purchases or is_admin(uid)

    def pick_key(uid: int, key: str | None) -> tuple[str | None, str | None]:
        if key:
            if is_admin(uid) or store.key_owner(key) == uid:
                return key, None
            return None, "Ключ не найден."  # не раскрываем, существует ли чужой ключ
        keys = store.keys_of(uid)
        if not keys:
            return None, "У вас пока нет ключей."
        return keys[0], None

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
        gb = to_int(parts[2], 0, MAX_GB) if len(parts) > 2 else 0
        if days is None or gb is None:
            await m.answer(usage)
            return
        owner = store.order_owner(order_id)
        if owner is not None and owner != uid and not is_admin(uid):
            await m.answer("Этот заказ уже оформлен на другого пользователя.")
            return
        try:
            res = await api.create_key(external_id=order_id, days=days, bytes_limit=gb * GB, notes=f"tg:{uid}")
        except VKTurnError as e:
            await m.answer(explain(e))
            return
        key_id = str(res["key"]).lower()
        if res.get("duplicate") and owner is None and not is_admin(uid):
            # Заказ уже есть на сервере, но не в локальной базе бота — не отдаём чужой ключ.
            await m.answer("Заказ уже обработан ранее. Обратитесь к продавцу.")
            return
        if owner is None:
            store.add(order_id, uid, key_id)
        text = ["Ваш ключ готов." if not res.get("duplicate") else "Ключ по этому заказу уже выдан (повтор)."]
        text.append(f"Ссылка для приложения:\n{res.get('link', '')}")
        if res.get("duration_days"):
            text.append(f"Срок {res['duration_days']} дн. начнётся с первой активации в приложении.")
        await m.answer("\n\n".join(text))

    @r.message(Command("status"))
    async def cmd_status(m: Message, command: CommandObject) -> None:
        key_arg, _ = split_args(command.args)
        key_id, err = pick_key(m.from_user.id, key_arg)
        if err:
            await m.answer(err)
            return
        try:
            await m.answer(describe(await api.get_key(key_id)))
        except VKTurnError as e:
            await m.answer(explain(e))

    @r.message(Command("traffic"))
    async def cmd_traffic(m: Message, command: CommandObject) -> None:
        key_arg, _ = split_args(command.args)
        key_id, err = pick_key(m.from_user.id, key_arg)
        if err:
            await m.answer(err)
            return
        try:
            k = await api.get_key(key_id)
        except VKTurnError as e:
            await m.answer(explain(e))
            return
        used, limit = int(k.get("bytes_used", 0) or 0), int(k.get("bytes_limit", 0) or 0)
        if limit:
            await m.answer(f"Использовано {fmt_bytes(used)} из {fmt_bytes(limit)}, "
                           f"осталось {fmt_bytes(max(limit - used, 0))}.")
        else:
            await m.answer(f"Использовано {fmt_bytes(used)}. Лимита нет.")

    @r.message(Command("extend"))
    async def cmd_extend(m: Message, command: CommandObject) -> None:
        uid = m.from_user.id
        if not may_purchase(uid):
            await m.answer("Оплата ещё не подтверждена. Обратитесь к продавцу.")
            return
        key_arg, rest = split_args(command.args)
        days = to_int(rest[0], 1, MAX_DAYS) if rest else cfg.default_days
        if days is None:
            await m.answer(f"Использование: /extend [ключ] [дней 1..{MAX_DAYS}]")
            return
        key_id, err = pick_key(uid, key_arg)
        if err:
            await m.answer(err)
            return
        try:
            # PATCH expires_days у бессрочного ключа ставит срок от сегодня и убирает бессрочность.
            if (await api.get_key(key_id)).get("days_left") == -1:
                await m.answer("Ключ бессрочный, продлевать нечего.")
                return
            res = await api.extend(key_id, days)
        except VKTurnError as e:
            await m.answer(explain(e))
            return
        msg = f"Продлено на {days} дн."
        if res.get("new_port"):
            msg += " Доступ восстановлен — приложение переподключится само, вводить ключ заново не нужно."
        await m.answer(msg)

    @r.message(Command("addtraffic"))
    async def cmd_addtraffic(m: Message, command: CommandObject) -> None:
        uid = m.from_user.id
        if not may_purchase(uid):
            await m.answer("Оплата ещё не подтверждена. Обратитесь к продавцу.")
            return
        key_arg, rest = split_args(command.args)
        gb = to_int(rest[0], 1, MAX_GB) if rest else None
        if gb is None:
            await m.answer("Использование: /addtraffic [ключ] <ГБ>")
            return
        key_id, err = pick_key(uid, key_arg)
        if err:
            await m.answer(err)
            return
        try:
            res = await api.add_traffic(key_id, gb * GB)
        except VKTurnError as e:
            await m.answer(explain(e))  # напр. 400 для безлимитного ключа
            return
        msg = f"Добавлено {gb} ГБ."
        if res.get("new_port"):
            msg += " Доступ восстановлен — приложение переподключится само."
        await m.answer(msg)

    @r.message(Command("unbind"))
    async def cmd_unbind(m: Message, command: CommandObject) -> None:
        key_arg, rest = split_args(command.args)
        key_id, err = pick_key(m.from_user.id, key_arg)
        if err:
            await m.answer(err)
            return
        if not rest or rest[0].lower() != "yes":
            await m.answer(
                "Старая привязка и конфиги перестанут работать; снова можно не раньше чем через 7 дней.\n"
                "Подтвердите: /unbind yes  (или /unbind <ключ> yes)"
            )
            return
        try:
            await api.unbind(key_id)
        except VKTurnError as e:
            await m.answer(explain(e))
            return
        await m.answer("Готово. Вставьте ту же ссылку-ключ в приложении на новом устройстве.")

    return r


async def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    try:
        cfg = Config()
    except KeyError as e:
        raise SystemExit(f"Не задана переменная окружения {e.args[0]} (см. README.md)")
    except ValueError as e:
        raise SystemExit(f"Неверная настройка: {e}")
    try:
        api = VKTurnClient(cfg.api_url, cfg.admin_token, pin=cfg.admin_pin)
    except ValueError as e:
        raise SystemExit(f"Неверная настройка: {e}")
    store = Store(cfg.db_path)
    bot = Bot(cfg.bot_token)
    dp = Dispatcher()
    dp.include_router(build_router(cfg, api, store))
    try:
        await dp.start_polling(bot)
    finally:
        await api.close()
        await bot.session.close()


if __name__ == "__main__":
    asyncio.run(main())
