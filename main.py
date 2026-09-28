#!/usr/bin/env python3
"""Ivy - Telegram group management & moderation bot (single-file v1.0)."""
# =========================================
# IMPORTS
# =========================================
from __future__ import annotations

import asyncio
import hashlib
import html
import json
import logging
import os
import random
import re
import secrets
import sqlite3
import sys
import time
import traceback
from collections import deque
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from zoneinfo import ZoneInfo

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from dotenv import load_dotenv
from sqlalchemy import (BigInteger, Boolean, Float, Index, Integer, String, Text,
                        UniqueConstraint, create_engine, delete, event, func, select)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker
from telegram import (BotCommand, ChatPermissions, LinkPreviewOptions, Update)
from telegram import InlineKeyboardButton as Btn
from telegram import InlineKeyboardMarkup as Kb
from telegram.constants import ChatMemberStatus as CMS
from telegram.constants import ChatType, ParseMode
from telegram.error import BadRequest, Forbidden, NetworkError, RetryAfter, TelegramError, TimedOut
from telegram.ext import (Application, CallbackQueryHandler, ChatMemberHandler, CommandHandler,
                          ContextTypes, MessageHandler, filters)

# =========================================
# CONFIGURATION
# =========================================
load_dotenv()


def _env(key: str, default: str = "") -> str:
    return os.getenv(key, default).strip()


BOT_TOKEN = _env("BOT_TOKEN")
try:
    OWNER_ID = int(_env("OWNER_ID") or 0)
except ValueError:
    OWNER_ID = 0
BOT_NAME = _env("BOT_NAME", "Ivy")
BOT_USERNAME = _env("BOT_USERNAME").lstrip("@")
DATABASE_URL = _env("DATABASE_URL", "sqlite:///bot.db")
LOG_LEVEL = _env("LOG_LEVEL", "INFO").upper()
TIMEZONE = _env("TIMEZONE", "Asia/Kolkata")
SUPPORT_URL = _env("SUPPORT_URL")
VERSION = "1.0.0"
START_TIME = time.time()
ANON_ADMIN_ID = 1087968824  # Telegram's "GroupAnonymousBot"


class SafeFormatter(logging.Formatter):
    """Formatter that can never leak the bot token (also inside tracebacks)."""

    def format(self, record):
        out = super().format(record)
        return out.replace(BOT_TOKEN, "***") if BOT_TOKEN else out


def setup_logging():
    fmt = SafeFormatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s")
    root = logging.getLogger()
    root.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))
    for handler in (logging.StreamHandler(),
                    RotatingFileHandler("bot.log", maxBytes=2_000_000, backupCount=2, encoding="utf-8")):
        handler.setFormatter(fmt)
        root.addHandler(handler)
    for noisy in ("httpx", "httpcore", "apscheduler"):  # httpx logs URLs that contain the token
        logging.getLogger(noisy).setLevel(logging.WARNING)


log = logging.getLogger("ivy")
ERRORS: deque = deque(maxlen=50)

# =========================================
# DATABASE
# =========================================
_IS_SQLITE = DATABASE_URL.startswith("sqlite")
engine = create_engine(DATABASE_URL, future=True,
                       connect_args={"check_same_thread": False, "timeout": 30} if _IS_SQLITE else {})
if _IS_SQLITE:
    @event.listens_for(engine, "connect")
    def _pragmas(conn, _):
        cur = conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA synchronous=NORMAL")
        cur.close()
SessionLocal = sessionmaker(engine, expire_on_commit=False)


@contextmanager
def db():
    s = SessionLocal()
    try:
        yield s
        s.commit()
    except Exception:
        s.rollback()
        raise
    finally:
        s.close()


# =========================================
# MODELS
# =========================================
class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    user_id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=False)
    username: Mapped[str | None] = mapped_column(String(64), index=True)
    first_name: Mapped[str | None] = mapped_column(String(128))
    last_name: Mapped[str | None] = mapped_column(String(128))
    is_bot: Mapped[bool] = mapped_column(Boolean, default=False)
    started: Mapped[bool] = mapped_column(Boolean, default=False)  # has opened a DM with the bot
    first_seen: Mapped[float] = mapped_column(Float, default=0)
    last_seen: Mapped[float] = mapped_column(Float, default=0)


class Group(Base):
    __tablename__ = "groups"
    group_id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=False)
    title: Mapped[str | None] = mapped_column(String(256))
    username: Mapped[str | None] = mapped_column(String(64))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    left: Mapped[bool] = mapped_column(Boolean, default=False)
    added_ts: Mapped[float] = mapped_column(Float, default=0)


class GroupSetting(Base):  # group_settings
    __tablename__ = "group_settings"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    group_id: Mapped[int] = mapped_column(BigInteger)
    key: Mapped[str] = mapped_column(String(64))
    value: Mapped[str] = mapped_column(Text)
    __table_args__ = (UniqueConstraint("group_id", "key"),)


class GroupAdmin(Base):  # group_admins (bot-level roles; group_id 0 = bot staff)
    __tablename__ = "group_admins"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    group_id: Mapped[int] = mapped_column(BigInteger, index=True)
    user_id: Mapped[int] = mapped_column(BigInteger, index=True)
    role: Mapped[str] = mapped_column(String(16))  # moderator / admin / trusted / staff
    added_by: Mapped[int] = mapped_column(BigInteger, default=0)
    ts: Mapped[float] = mapped_column(Float, default=0)
    __table_args__ = (UniqueConstraint("group_id", "user_id", "role"),)


class Warning(Base):
    __tablename__ = "warnings"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    group_id: Mapped[int] = mapped_column(BigInteger)
    user_id: Mapped[int] = mapped_column(BigInteger)
    by_id: Mapped[int] = mapped_column(BigInteger, default=0)
    reason: Mapped[str | None] = mapped_column(Text)
    ts: Mapped[float] = mapped_column(Float, default=0)
    __table_args__ = (Index("ix_warn_gu", "group_id", "user_id"),)


class Filter(Base):
    __tablename__ = "filters"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    group_id: Mapped[int] = mapped_column(BigInteger, index=True)
    pattern: Mapped[str] = mapped_column(Text)
    kind: Mapped[str] = mapped_column(String(10))    # word / partial / exact / regex
    action: Mapped[str] = mapped_column(String(10))  # reply / block / delete / warn / mute / ban
    response: Mapped[str | None] = mapped_column(Text)
    created_by: Mapped[int] = mapped_column(BigInteger, default=0)


class Note(Base):
    __tablename__ = "notes"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    group_id: Mapped[int] = mapped_column(BigInteger)
    name: Mapped[str] = mapped_column(String(64))
    text: Mapped[str | None] = mapped_column(Text)
    media_type: Mapped[str | None] = mapped_column(String(16))
    file_id: Mapped[str | None] = mapped_column(String(256))
    __table_args__ = (UniqueConstraint("group_id", "name"),)


class Lock(Base):  # locks: member_locked / admin_locked stored separately
    __tablename__ = "locks"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    group_id: Mapped[int] = mapped_column(BigInteger)
    lock_type: Mapped[str] = mapped_column(String(24))
    member_locked: Mapped[bool] = mapped_column(Boolean, default=False)
    admin_locked: Mapped[bool] = mapped_column(Boolean, default=False)
    __table_args__ = (UniqueConstraint("group_id", "lock_type"),)


class AdminLog(Base):
    __tablename__ = "admin_logs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    group_id: Mapped[int] = mapped_column(BigInteger, index=True)
    action: Mapped[str] = mapped_column(String(24))
    executor_id: Mapped[int] = mapped_column(BigInteger, default=0)
    target_id: Mapped[int] = mapped_column(BigInteger, default=0, index=True)
    reason: Mapped[str | None] = mapped_column(Text)
    ts: Mapped[float] = mapped_column(Float, default=0)


class ScheduledTask(Base):
    __tablename__ = "scheduled_tasks"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    kind: Mapped[str] = mapped_column(String(24))
    group_id: Mapped[int] = mapped_column(BigInteger, default=0)
    user_id: Mapped[int] = mapped_column(BigInteger, default=0)
    run_at: Mapped[float] = mapped_column(Float, index=True)
    payload: Mapped[str | None] = mapped_column(Text)
    done: Mapped[bool] = mapped_column(Boolean, default=False)


class XP(Base):
    __tablename__ = "xp"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    group_id: Mapped[int] = mapped_column(BigInteger)
    user_id: Mapped[int] = mapped_column(BigInteger)
    xp: Mapped[int] = mapped_column(Integer, default=0)
    level: Mapped[int] = mapped_column(Integer, default=0)
    messages: Mapped[int] = mapped_column(Integer, default=0)
    last_xp: Mapped[float] = mapped_column(Float, default=0)
    __table_args__ = (UniqueConstraint("group_id", "user_id"),)


class Economy(Base):
    __tablename__ = "economy"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    group_id: Mapped[int] = mapped_column(BigInteger)
    user_id: Mapped[int] = mapped_column(BigInteger)
    coins: Mapped[int] = mapped_column(Integer, default=0)
    last_daily: Mapped[float] = mapped_column(Float, default=0)
    last_weekly: Mapped[float] = mapped_column(Float, default=0)
    last_monthly: Mapped[float] = mapped_column(Float, default=0)
    __table_args__ = (UniqueConstraint("group_id", "user_id"),)


class ShopItem(Base):
    __tablename__ = "shop_items"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    group_id: Mapped[int] = mapped_column(BigInteger, index=True)
    name: Mapped[str] = mapped_column(String(64))
    price: Mapped[int] = mapped_column(Integer)
    description: Mapped[str | None] = mapped_column(Text)


class Inventory(Base):
    __tablename__ = "inventory"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    group_id: Mapped[int] = mapped_column(BigInteger)
    user_id: Mapped[int] = mapped_column(BigInteger)
    item: Mapped[str] = mapped_column(String(64))
    __table_args__ = (Index("ix_inv_gu", "group_id", "user_id"),)


class BotSetting(Base):
    __tablename__ = "bot_settings"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text)


class BroadcastLog(Base):
    __tablename__ = "broadcast_logs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    owner_id: Mapped[int] = mapped_column(BigInteger)
    target: Mapped[str] = mapped_column(String(16))
    total: Mapped[int] = mapped_column(Integer, default=0)
    sent: Mapped[int] = mapped_column(Integer, default=0)
    failed: Mapped[int] = mapped_column(Integer, default=0)
    preview: Mapped[str | None] = mapped_column(Text)
    ts: Mapped[float] = mapped_column(Float, default=0)


class Verification(Base):
    __tablename__ = "verification"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    group_id: Mapped[int] = mapped_column(BigInteger)
    user_id: Mapped[int] = mapped_column(BigInteger)
    verified: Mapped[bool] = mapped_column(Boolean, default=False)
    msg_id: Mapped[int] = mapped_column(BigInteger, default=0)
    created: Mapped[float] = mapped_column(Float, default=0)
    __table_args__ = (UniqueConstraint("group_id", "user_id"),)


class MsgLog(Base):  # lets /delall, /delmedia, /topchatters, /activity work (Bot API has no history)
    __tablename__ = "msglog"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    group_id: Mapped[int] = mapped_column(BigInteger)
    message_id: Mapped[int] = mapped_column(BigInteger)
    user_id: Mapped[int] = mapped_column(BigInteger)
    mtype: Mapped[str] = mapped_column(String(16))
    ts: Mapped[float] = mapped_column(Float)
    __table_args__ = (Index("ix_ml_gt", "group_id", "ts"), Index("ix_ml_gu", "group_id", "user_id"))


class JoinLog(Base):
    __tablename__ = "join_log"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    group_id: Mapped[int] = mapped_column(BigInteger)
    user_id: Mapped[int] = mapped_column(BigInteger)
    event: Mapped[str] = mapped_column(String(8))  # join / leave
    ts: Mapped[float] = mapped_column(Float)
    __table_args__ = (Index("ix_jl_gt", "group_id", "ts"), Index("ix_jl_u", "user_id"))


# ---------- settings (per-group with global-default fallback, cached) ----------
DEFAULTS = {
    "warn_limit": 3, "warn_action": "mute", "warn_mute_minutes": 60,
    "antispam": True, "antiflood": True, "antiraid": False, "antibot": False, "anticaps": False,
    "antiemoji": False, "antimention": False, "antilink": False, "antiforward": False,
    "antichannel": False, "antisticker": False, "antigif": False, "antimedia": False,
    "antinsfw": False, "captcha": False, "raidmode": False,
    "flood_limit": 6, "flood_window": 5, "caps_percent": 70, "caps_min": 12, "emoji_limit": 10,
    "mention_limit": 5, "raid_threshold": 8, "raid_window": 60, "raid_minutes": 10,
    "raid_lockdown": False, "captcha_timeout": 5,
    "auto_delete": True, "auto_warn": True, "auto_mute": False, "auto_ban": False, "auto_mute_minutes": 30,
    "adminprotect": False, "adminmoderation": False, "lock_owner_exempt": True,
    "welcome": True, "goodbye": False, "clean_service": False,
    "xp": True, "xp_cooldown": 60, "xp_announce": True,
    "economy": True, "daily_amount": 100, "weekly_amount": 700, "monthly_amount": 3000,
    "language": "en", "timezone": TIMEZONE, "prefix": "", "log_chat": 0, "pin_notify": False,
    "filters_on": True,
}
_SC: dict[int, dict] = {}
_BC: dict[str, object] = {}


def _load_group(gid: int) -> dict:
    if gid not in _SC:
        with db() as s:
            rows = s.execute(select(GroupSetting.key, GroupSetting.value).where(GroupSetting.group_id == gid)).all()
        _SC[gid] = {k: json.loads(v) for k, v in rows}
    return _SC[gid]


def bget(key: str, default=None):
    if not _BC:
        with db() as s:
            for k, v in s.execute(select(BotSetting.key, BotSetting.value)).all():
                _BC[k] = json.loads(v)
        _BC["__loaded"] = True
    return _BC.get(key, default)


def bset(key: str, value):
    bget("__x")
    with db() as s:
        row = s.get(BotSetting, key)
        if row:
            row.value = json.dumps(value)
        else:
            s.add(BotSetting(key=key, value=json.dumps(value)))
    _BC[key] = value


def gget(gid: int, key: str, default=None):
    d = _load_group(gid)
    if key in d:
        return d[key]
    g = bget("default:" + key)
    if g is not None:
        return g
    return DEFAULTS.get(key, default)


def gset(gid: int, key: str, value):
    with db() as s:
        row = s.execute(select(GroupSetting).where(GroupSetting.group_id == gid, GroupSetting.key == key)).scalar()
        if row:
            row.value = json.dumps(value)
        else:
            s.add(GroupSetting(group_id=gid, key=key, value=json.dumps(value)))
    _load_group(gid)[key] = value


def init_db():
    Base.metadata.create_all(engine)
    log.info("Database ready (%s)", "sqlite" if _IS_SQLITE else "external")


# =========================================
# HELPERS
# =========================================
NOPREV = LinkPreviewOptions(is_disabled=True)
_BG: set = set()
_SEEN: dict = {}
_RC: dict = {}
_GEN: dict[int, bool] = {}
IMPL: dict = {}


def impl(*names):
    def deco(fn):
        for n in names:
            IMPL[n] = fn
        return fn
    return deco


def h(x) -> str:
    return html.escape(str(x), quote=False)


def bg(coro):
    t = asyncio.create_task(coro)
    _BG.add(t)
    t.add_done_callback(_BG.discard)
    return t


def fmt_dur(sec) -> str:
    sec, parts = int(sec), []
    for n, u in ((86400, "d"), (3600, "h"), (60, "m"), (1, "s")):
        if sec >= n:
            parts.append(f"{sec // n}{u}")
            sec %= n
    return " ".join(parts) or "0s"


def parse_duration(s):
    m = re.fullmatch(r"(\d+)\s*([smhdw])", (s or "").lower())
    if not m:
        return None
    v = int(m[1]) * {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}[m[2]]
    return v if 60 <= v <= 365 * 86400 else None


def tz_of(gid: int):
    try:
        return ZoneInfo(gget(gid, "timezone", TIMEZONE))
    except Exception:
        return timezone.utc


def fmt_ts(ts: float, gid: int = 0) -> str:
    return datetime.fromtimestamp(ts, tz_of(gid) if gid else ZoneInfo(TIMEZONE)).strftime("%Y-%m-%d %H:%M")


def is_group(chat) -> bool:
    return chat is not None and chat.type in (ChatType.GROUP, ChatType.SUPERGROUP)


def upsert_user(u) -> None:
    sig = (u.username, u.first_name, u.last_name)
    old = _SEEN.get(u.id)
    if old and old[0] == sig and time.time() - old[1] < 600:
        return
    _SEEN[u.id] = (sig, time.time())
    with db() as s:
        row = s.get(User, u.id)
        if not row:
            row = User(user_id=u.id, first_seen=time.time())
            s.add(row)
        row.username = (u.username or "").lower() or None
        row.first_name, row.last_name, row.is_bot, row.last_seen = u.first_name, u.last_name, u.is_bot, time.time()


def track(update: Update) -> None:
    u, c = update.effective_user, update.effective_chat
    if u:
        upsert_user(u)
        if c and c.type == ChatType.PRIVATE:
            with db() as s:
                row = s.get(User, u.id)
                if row and not row.started:
                    row.started = True
    if is_group(c):
        key = ("g", c.id)
        if key not in _SEEN or _SEEN[key][0] != c.title:
            _SEEN[key] = (c.title, time.time())
            with db() as s:
                g = s.get(Group, c.id)
                if not g:
                    g = Group(group_id=c.id, added_ts=time.time())
                    s.add(g)
                g.title, g.username, g.left = c.title, c.username, False


def group_enabled(gid: int) -> bool:
    if gid not in _GEN:
        with db() as s:
            g = s.get(Group, gid)
            _GEN[gid] = True if not g else bool(g.enabled)
    return _GEN[gid]


def display(uid: int) -> str:
    with db() as s:
        u = s.get(User, uid)
    if u:
        name = ((u.first_name or "") + (" " + u.last_name if u.last_name else "")).strip()
        if name:
            return name
    return f"User {uid}"


def mention(uid: int, name: str | None = None) -> str:
    return f'<a href="tg://user?id={uid}">{h(name or display(uid))}</a>'


async def reply(update: Update, text: str, **kw):
    kw.setdefault("parse_mode", ParseMode.HTML)
    kw.setdefault("link_preview_options", NOPREV)
    msg, chat = update.effective_message, update.effective_chat
    try:
        return await msg.reply_text(text[:4000], **kw)
    except BadRequest as e:
        if "not found" in str(e).lower():
            return await chat.send_message(text[:4000], **kw)
        if "parse" in str(e).lower():
            kw["parse_mode"] = None
            return await msg.reply_text(re.sub(r"<[^>]+>", "", text)[:4000], **kw)
        raise


async def say(bot, chat_id, text: str, **kw):
    kw.setdefault("parse_mode", ParseMode.HTML)
    kw.setdefault("link_preview_options", NOPREV)
    try:
        return await bot.send_message(chat_id, text[:4000], **kw)
    except BadRequest as e:
        if "parse" in str(e).lower():
            kw["parse_mode"] = None
            return await bot.send_message(chat_id, re.sub(r"<[^>]+>", "", text)[:4000], **kw)
        raise


async def _later_delete(msg, delay):
    await asyncio.sleep(delay)
    try:
        await msg.delete()
    except TelegramError:
        pass


async def notice(bot, chat_id, text: str, secs: int = 10):
    try:
        m = await say(bot, chat_id, text)
        bg(_later_delete(m, secs))
    except TelegramError:
        pass


BTN_RE = re.compile(r"\{button:([^|}]+)\|([^}]+)\}")


def split_buttons(tpl: str):
    btns = BTN_RE.findall(tpl or "")
    text = BTN_RE.sub("", tpl or "").strip()
    return text, (Kb([[Btn(t.strip(), url=u.strip())] for t, u in btns]) if btns else None)


def render_tpl(tpl: str, user, chat, count: int) -> str:
    uname = f"@{user.username}" if user.username else h(user.first_name)
    for k, v in {"{user}": h(user.full_name), "{username}": uname, "{mention}": mention(user.id, user.full_name),
                 "{id}": str(user.id), "{group}": h(chat.title or ""), "{count}": str(count)}.items():
        tpl = tpl.replace(k, v)
    return tpl


def db_count(model, *conds) -> int:
    with db() as s:
        return s.execute(select(func.count()).select_from(model).where(*conds)).scalar() or 0


# ---------- scheduler (persisted in scheduled_tasks) ----------
SCHED = AsyncIOScheduler(timezone="UTC")
APP: Application | None = None


def schedule_task(kind: str, gid: int, uid: int, run_at: float, payload: dict | None = None) -> int:
    with db() as s:
        t = ScheduledTask(kind=kind, group_id=gid, user_id=uid, run_at=run_at, payload=json.dumps(payload or {}))
        s.add(t)
        s.flush()
        tid = t.id
    _add_job(tid, run_at)
    return tid


def _add_job(tid: int, run_at: float):
    SCHED.add_job(run_task, "date", run_date=datetime.fromtimestamp(max(run_at, time.time() + 2), tz=timezone.utc),
                  args=[tid], id=f"task{tid}", replace_existing=True, misfire_grace_time=86400)


def cancel_task(tid: int):
    try:
        SCHED.remove_job(f"task{tid}")
    except Exception:
        pass
    with db() as s:
        t = s.get(ScheduledTask, tid)
        if t:
            t.done = True


def restore_tasks():
    with db() as s:
        rows = s.execute(select(ScheduledTask.id, ScheduledTask.run_at).where(ScheduledTask.done == False)).all()  # noqa: E712
    for tid, run_at in rows:
        _add_job(tid, run_at)
    log.info("Restored %d scheduled task(s)", len(rows))


# =========================================
# PERMISSIONS
# =========================================
LV = {"everyone": 0, "moderator": 1, "admin": 2, "trusted": 3, "group_owner": 4, "staff": 5, "owner": 6}
ROLE_NAMES = ["Member", "Moderator", "Admin", "Trusted Admin", "Group Owner", "Bot Staff", "Bot Owner"]
NEED = {"can_restrict_members": "Ban users", "can_delete_messages": "Delete messages",
        "can_pin_messages": "Pin messages", "can_promote_members": "Add new admins"}


async def tg_status(bot, chat_id: int, uid: int):
    key = (chat_id, uid)
    c = _RC.get(key)
    if c and time.time() - c[0] < 30:
        return c[1]
    try:
        st = (await bot.get_chat_member(chat_id, uid)).status
    except TelegramError:
        st = None
    _RC[key] = (time.time(), st)
    return st


async def get_role(bot, chat_id: int, uid: int) -> int:
    if uid == OWNER_ID and OWNER_ID:
        return 6
    if uid == ANON_ADMIN_ID:
        return 2
    with db() as s:
        rows = s.execute(select(GroupAdmin.role).where(GroupAdmin.user_id == uid,
                                                       GroupAdmin.group_id.in_([0, chat_id]))).scalars().all()
    if "staff" in rows:
        return 5
    st = await tg_status(bot, chat_id, uid) if chat_id < 0 else None
    lvl = 4 if st == CMS.OWNER else 0
    if "trusted" in rows:
        lvl = max(lvl, 3)
    if st == CMS.ADMINISTRATOR or "admin" in rows:
        lvl = max(lvl, 2)
    if "moderator" in rows:
        lvl = max(lvl, 1)
    return lvl


async def bot_can(ctx, chat_id: int, right: str) -> bool:
    try:
        m = await ctx.bot.get_chat_member(chat_id, ctx.bot.id)
    except TelegramError:
        return False
    return m.status == CMS.OWNER or (m.status == CMS.ADMINISTRATOR and bool(getattr(m, right, False)))


async def safety(ctx, chat_id: int, exec_id: int, tid: int, right="can_restrict_members", rank_check=True):
    """Steps 1-6 of the moderation safety pipeline. Returns an error string or None."""
    if tid == ctx.bot.id:
        return "🤖 I won't do that to myself."
    if rank_check:
        if tid == exec_id:
            return "🙅 You can't do that to yourself."
        if tid == OWNER_ID and exec_id != OWNER_ID:
            return "🚫 That's the bot owner."
        er, tr = await get_role(ctx.bot, chat_id, exec_id), await get_role(ctx.bot, chat_id, tid)
        if tr >= er:
            return "🚫 You can't act on someone with an equal or higher rank."
        if gget(chat_id, "adminprotect") and tr >= 2 and er < 4:
            return "🛡️ Admin protection is on: only the group owner can act on admins."
        try:
            if (await ctx.bot.get_chat_member(chat_id, tid)).status == CMS.OWNER:
                return "🚫 Nobody can act on the group owner."
        except TelegramError:
            pass
    if not await bot_can(ctx, chat_id, right):
        return f"❌ I need to be an admin with the “{NEED[right]}” permission first."
    return None


async def resolve_target(update: Update, ctx):
    """Reply -> text_mention -> numeric ID -> @username (known users). Returns (user_id|None, remaining args)."""
    msg, args = update.effective_message, list(ctx.args or [])
    r = msg.reply_to_message
    if r and r.from_user and r.from_user.id != ANON_ADMIN_ID:
        upsert_user(r.from_user)
        return r.from_user.id, args
    for e in msg.entities or []:
        if e.type == "text_mention" and e.user:
            upsert_user(e.user)
            return e.user.id, args[1:]
    if not args:
        return None, args
    a = args[0]
    if re.fullmatch(r"-?\d{5,}", a):
        return int(a), args[1:]
    if a.startswith("@"):
        with db() as s:
            uid = s.execute(select(User.user_id).where(User.username == a[1:].lower())).scalar()
        if uid:
            return uid, args[1:]
        try:
            c = await ctx.bot.get_chat(a)
            if c.type == ChatType.PRIVATE:
                return c.id, args[1:]
        except TelegramError:
            pass
    return None, args


NO_TARGET = ("🎯 I couldn't identify the target. Reply to their message, use a numeric ID, or an @username "
             "of someone I've seen in a chat (Telegram doesn't let bots look up unknown usernames).")


async def alog(bot, gid: int, action: str, executor: int, target: int, reason: str = "—"):
    with db() as s:
        s.add(AdminLog(group_id=gid, action=action, executor_id=executor, target_id=target,
                       reason=(reason or "—")[:500], ts=time.time()))
    lc = gget(gid, "log_chat", 0) if gid else 0
    if lc:
        try:
            await say(bot, lc, f"📋 <b>{action}</b>\nGroup: <code>{gid}</code>\nBy: {mention(executor)}\n"
                               f"Target: {mention(target) if target else '—'}\nReason: {h(reason)}")
        except TelegramError:
            pass


async def restore_perms(bot, chat_id: int, uid: int):
    chat = await bot.get_chat(chat_id)
    perms = chat.permissions or ChatPermissions.all_permissions()
    await bot.restrict_chat_member(chat_id, uid, perms, use_independent_chat_permissions=True)
    _RC.pop((chat_id, uid), None)


# =========================================
# COMMAND REGISTRY
# =========================================
# category|name (or alias=target)|description|usage|perm (e/m/a/t/g/s/o)|flags (d = works in DMs)
REGISTRY = """
Bot|start|Start the bot|/start|e|d
Bot|help|Help and command center|/help|e|d
Bot|command|Browse or search commands|/command [name]|e|d
Bot|commands=command
Bot|about|About this bot|/about|e|d
Bot|ping|Check bot latency|/ping|e|d
Bot|status|Bot status, or a member's chat status|/status [@user]|e|d
Bot|uptime|Show bot uptime|/uptime|e|d
Bot|bot|Owner control panel|/bot|o|d
Bot|botstatus|Detailed bot status|/botstatus|o|d
Bot|boton|Enable the bot globally|/boton|o|d
Bot|botoff|Disable the bot globally|/botoff|o|d
Bot|restart|Restart the bot process|/restart|o|d
Bot|maintenance|Show or toggle maintenance mode|/maintenance [on/off]|o|d
Bot|maintenance_on|Enable maintenance mode|/maintenance_on|o|d
Bot|maintenance_off|Disable maintenance mode|/maintenance_off|o|d
Bot|offall|Disable the bot in every group|/offall|o|d
Bot|onall|Enable the bot in every group|/onall|o|d
Bot|offgroup|Disable the bot in one group|/offgroup [chat_id]|o|d
Bot|ongroup|Enable the bot in one group|/ongroup [chat_id]|o|d
Bot|groups|List and remotely manage groups|/groups|o|d
Bot|groupinfo|Group details|/groupinfo [chat_id]|o|d
Bot|gstats|Group statistics|/gstats [chat_id]|o|d
Bot|gsettings|Group settings dump|/gsettings [chat_id]|o|d
Bot|users|List known users|/users|o|d
Bot|userinfo|User details by ID|/userinfo <id>|o|d
Bot|broadcast|Broadcast to groups and/or users|/broadcast <text> or reply|o|d
Bot|gbroadcast|Broadcast to groups only|/gbroadcast <text> or reply|o|d
Bot|announce|Post an announcement in a group|/announce [chat_id] <text>|o|d
Bot|globalsettings|Show global defaults|/globalsettings|o|d
Bot|setglobal|Set a global default|/setglobal <key> <value>|o|d
Bot|logs|Admin action logs|/logs [chat_id]|o|d
Bot|errors|Recent bot errors|/errors|o|d
Bot|health|Health check|/health|o|d
Bot|database|Database statistics|/database|o|d
Bot|backup|Send a database backup|/backup|o|d
Bot|botinfo|Bot information|/botinfo|e|d
Bot|version|Bot version|/version|e|d
Bot|features|Feature overview|/features|e|d
Bot|changelog|What's new|/changelog|e|d
Bot|support|Get support|/support|e|d
Administration|admins|List group admins|/admins|e
Administration|owner|Show the group owner|/owner|e
Administration|admin|Show a member's rank|/admin [@user]|e
Administration|promote|Promote to Telegram admin|/promote @user [title]|t
Administration|demote|Demote a Telegram admin|/demote @user|t
Administration|setadmin|Give a bot-level role|/setadmin @user [moderator/admin]|g
Administration|deladmin|Remove a bot-level role|/deladmin @user|g
Administration|trust|Mark a member as trusted admin|/trust @user|g
Administration|untrust|Remove trusted status|/untrust @user|g
Administration|trusted|List trusted admins|/trusted|e
Administration|staff|List or manage bot staff|/staff [add/remove @user]|e|d
Administration|adminmoderation|Apply auto-moderation to admins too|/adminmoderation on/off|g
Administration|adminprotect|Only the group owner may act on admins|/adminprotect on/off|g
Administration|pin|Pin the replied message|/pin|a
Administration|unpin|Unpin a message|/unpin [all]|a
Administration|pinned|Show the pinned message|/pinned|e
Administration|silent|Pin without notification|/silent|a
Administration|notify|Pin with notification|/notify|a
Administration|schedule|Schedule an announcement|/schedule <time> <text>|a
Moderation|ban|Ban a member|/ban @user [reason]|a
Moderation|unban|Unban a member|/unban @user|a
Moderation|tban|Temporarily ban|/tban @user <time> [reason]|a
Moderation|kick|Kick a member (can rejoin)|/kick @user [reason]|m
Moderation|softban|Ban and unban, deleting their messages|/softban @user [reason]|a
Moderation|mute|Mute a member|/mute @user [time] [reason]|m
Moderation|unmute|Unmute a member|/unmute @user|m
Moderation|tmute|Temporarily mute|/tmute @user <time> [reason]|m
Moderation|warn|Warn a member|/warn @user [reason]|m
Moderation|unwarn|Remove the latest warning|/unwarn @user|m
Moderation|warnings|View warnings|/warnings [@user]|e
Moderation|resetwarns|Reset all warnings|/resetwarns @user|a
Moderation|warnlimit|Set the warning limit|/warnlimit [number]|a
Moderation|warnaction|Set the action at the limit|/warnaction [mute/kick/ban]|a
Moderation|restrict|Restrict specific rights|/restrict @user <text/media/stickers/polls/links/info/invite/pin/all>|a
Moderation|unrestrict|Restore default rights|/unrestrict @user|a
Moderation|del|Delete the replied message|/del|m
Moderation|purge|Delete from the replied message to here|/purge|a
Moderation|purgefrom|Mark the start of a purge range|/purgefrom|a
Moderation|purgeto|Delete from the marked message to here|/purgeto|a
Moderation|clear|Delete the last N message ids|/clear <n>|a
Moderation|delall|Delete a user's recent messages|/delall @user|a
Moderation|delmedia|Delete recent media messages|/delmedia [n] [@user]|a
Moderation|deltext|Delete recent text messages|/deltext [n] [@user]|a
Moderation|delsticker|Delete recent stickers|/delsticker [n] [@user]|a
Moderation|delphoto|Delete recent photos|/delphoto [n] [@user]|a
Moderation|delvideo|Delete recent videos|/delvideo [n] [@user]|a
Locks|lock|Lock content for members|/lock <type...>|a
Locks|unlock|Unlock content|/unlock <type...>|a
Locks|lockadmin|Lock content for members AND admins|/lockadmin <type...>|a
Locks|unlockadmin|Remove the admin lock only|/unlockadmin <type...>|a
Locks|locks|Show and edit locks|/locks|e
Security|antispam|Repeated-message protection|/antispam on/off|a
Security|antiflood|Flood protection|/antiflood on/off/<limit>|a
Security|antiraid|Raid detection|/antiraid on/off/<joins>|a
Security|antibot|Block bots added by non-admins|/antibot on/off|a
Security|anticaps|Excessive capitals|/anticaps on/off/<percent>|a
Security|antiemoji|Emoji spam|/antiemoji on/off/<limit>|a
Security|antimention|Mention spam|/antimention on/off/<limit>|a
Security|antilink|Delete links|/antilink on/off|a
Security|antiforward|Delete forwards|/antiforward on/off|a
Security|antichannel|Block channel-identity messages|/antichannel on/off|a
Security|antisticker|Delete stickers|/antisticker on/off|a
Security|antigif|Delete GIFs|/antigif on/off|a
Security|antimedia|Delete media|/antimedia on/off|a
Security|antinsfw|Keyword-based NSFW filter|/antinsfw on/off|a
Security|captcha|Human verification for new members|/captcha on/off/<minutes>|a
Security|verify|Manually verify a member|/verify @user|a
Security|unverify|Require verification again|/unverify @user|a
Security|verification|Verification status|/verification|a
Security|raidmode|Manual raid mode|/raidmode on/off|a
Security|security|Security panel|/security|a
Filters|filter|Add a filter|/filter [kind:]word response|a
Filters|addfilter=filter
Filters|delfilter|Delete a filter|/delfilter <word>|a
Filters|filters|List filters|/filters|e
Filters|clearfilters|Delete all filters|/clearfilters|g
Filters|blockword|Block a word (auto-action)|/blockword <word> [delete/warn/mute/ban]|a
Filters|unblockword|Unblock a word|/unblockword <word>|a
Filters|blockedwords|List blocked words|/blockedwords|a
Filters|regex|Block a regex pattern|/regex <pattern> [action]|a
Filters|addregex=regex
Filters|delregex|Delete a regex|/delregex <pattern>|a
Filters|autowarn|Warn on blocked content|/autowarn on/off|a
Filters|automute|Mute on blocked content|/automute on/off|a
Filters|autoban|Ban on blocked content|/autoban on/off|a
Filters|autodelete|Delete blocked content|/autodelete on/off|a
Welcome|welcome|Welcome status/preview/toggle|/welcome [on/off/preview]|a
Welcome|setwelcome|Set the welcome message|/setwelcome <text> or reply|a
Welcome|delwelcome|Delete the custom welcome|/delwelcome|a
Welcome|goodbye|Goodbye status/toggle|/goodbye [on/off/preview]|a
Welcome|setgoodbye|Set the goodbye message|/setgoodbye <text> or reply|a
Welcome|delgoodbye|Delete the custom goodbye|/delgoodbye|a
Welcome|greet=welcome
Welcome|newmembers|Members who joined in 24h|/newmembers|m
Welcome|membercount|Member count|/membercount|e
Welcome|joinstats|Join/leave statistics|/joinstats|m
Rules|setrules|Set the rules|/setrules <text> or reply|a
Rules|rules|Show the rules|/rules|e
Rules|delrules|Delete the rules|/delrules|a
Rules|save|Save a note|/save <name> <text> or reply|a
Rules|get|Get a note|/get <name>|e
Rules|note=get
Rules|notes|List notes|/notes|e
Rules|delnote|Delete a note|/delnote <name>|a
Rules|clearnotes|Delete all notes|/clearnotes|g
Statistics|stats|Chat statistics|/stats|e
Statistics|chatstats=stats
Statistics|userstats|User statistics|/userstats [@user]|e
Statistics|topusers|Most active users (all-time)|/topusers|e
Statistics|topchatters|Most active users (24h)|/topchatters|e
Statistics|messages|Message counts|/messages [@user]|e
Statistics|activity|Hourly activity chart (24h)|/activity|e
Statistics|leaderboard|XP leaderboard|/leaderboard|e
User|info|User information|/info [@user]|e|d
User|id|Show IDs|/id [@user]|e|d
User|getid=id
User|whois|Detailed user information|/whois [@user]|m
User|avatar|Show a profile picture|/avatar [@user]|e
User|profile|Your profile card|/profile [@user]|e
User|history|Moderation history|/history [@user]|m
User|joins|Join history|/joins [@user]|m
User|username|Username lookup|/username [@user/id]|e|d
XP|rank|Show XP rank card|/rank [@user]|e
XP|xp=rank
XP|level=rank
XP|setxp|Set a member's XP|/setxp @user <amount>|a
XP|resetxp|Reset XP|/resetxp [@user/all]|a
XP|xpon|Enable XP|/xpon|a
XP|xpoff|Disable XP|/xpoff|a
XP|levels|Level thresholds|/levels|e
XP|top=leaderboard
XP|rewards|Level rewards|/rewards [set <level> <coins>]|e
Economy|balance|Your coins|/balance [@user]|e
Economy|daily|Claim daily coins|/daily|e
Economy|weekly|Claim weekly coins|/weekly|e
Economy|monthly|Claim monthly coins|/monthly|e
Economy|pay|Send coins|/pay @user <amount>|e
Economy|give=pay
Economy|economy|Economy settings|/economy [on/off/daily/weekly/monthly <n>]|e
Economy|rich|Richest members|/rich|e
Economy|shop|Browse or edit the shop|/shop [add <name> <price> [desc]/remove <name>]|e
Economy|buy|Buy a shop item|/buy <name>|e
Fun|8ball|Ask the magic 8-ball|/8ball <question>|e|d
Fun|dice|Roll a Telegram dice|/dice|e|d
Fun|coin|Flip a coin|/coin|e|d
Fun|coinflip=coin
Fun|roll|Roll dice (e.g. 2d6)|/roll [NdM]|e|d
Fun|choose|Pick one option|/choose a, b, c|e|d
Fun|ship|Compatibility meter|/ship name1 name2|e|d
Fun|love=ship
Fun|hug|Hug someone|/hug @user|e|d
Fun|slap|Slap someone|/slap @user|e|d
Fun|highfive|High-five someone|/highfive @user|e|d
Fun|joke|Tell a joke|/joke|e|d
Fun|quote|Random quote|/quote|e|d
Fun|truth|Truth question|/truth|e|d
Fun|dare|Dare challenge|/dare|e|d
Settings|settings|Settings panel|/settings [set <key> <value>]|a
Settings|setprefix|Custom command prefix|/setprefix <char/off>|a
Settings|language|Bot language|/language [en/hi]|a
Settings|timezone|Group timezone|/timezone [Area/City]|a
"""
PERM_CODE = {"e": 0, "m": 1, "a": 2, "t": 3, "g": 4, "s": 5, "o": 6}
CATEGORIES = [("🛡️", "Moderation"), ("🔐", "Security"), ("👑", "Administration"), ("🔒", "Locks"),
              ("👋", "Welcome"), ("📝", "Filters"), ("📜", "Rules"), ("📊", "Statistics"), ("👤", "User"),
              ("⭐", "XP"), ("💰", "Economy"), ("🎮", "Fun"), ("🤖", "Bot"), ("⚙️", "Settings")]
COMMANDS: dict[str, dict[str, dict]] = {c: {} for _, c in CATEGORIES}
META: dict[str, dict] = {}


def build_registry():
    for line in REGISTRY.strip().splitlines():
        p = line.split("|")
        cat, name = p[0], p[1]
        if "=" in name:
            alias, target = name.split("=")
            m = dict(META[target], name=alias, alias_of=target, desc=f"Alias of /{target}")
        else:
            m = {"name": name, "cat": cat, "desc": p[2], "usage": p[3], "perm": PERM_CODE[p[4]],
                 "dm": len(p) > 5 and "d" in p[5], "alias_of": None, "target": name}
        m["cat"] = cat
        META[m["name"]] = m
        COMMANDS[cat][m["name"]] = {"description": m["desc"], "usage": m["usage"],
                                    "permission": ROLE_NAMES[m["perm"]], "alias_of": m["alias_of"]}
    missing = [n for n, m in META.items() if m["target"] not in IMPL]
    if missing:
        raise RuntimeError(f"Commands without implementation: {missing}")
    log.info("Command registry: %d commands", len(META))


# =========================================
# COMMAND DISPATCH (maintenance, group on/off, permission checks)
# =========================================
MAINT_TEXT = {"en": "🔴 <b>IVY IS CURRENTLY IN MAINTENANCE MODE.</b>\n\nPlease try again later.",
              "hi": "🔴 <b>IVY अभी मेंटेनेंस मोड में है।</b>\n\nकृपया बाद में प्रयास करें।"}


def bot_online() -> bool:
    return bool(bget("bot_enabled", True)) and not bget("maintenance_mode", False)


async def run_command(update: Update, ctx, name: str):
    msg, user, chat = update.effective_message, update.effective_user, update.effective_chat
    if not msg or not user or not chat:
        return
    track(update)
    meta = META[name]
    is_owner = user.id == OWNER_ID and OWNER_ID != 0
    if not is_owner:
        if not bot_online():
            if chat.type == ChatType.PRIVATE or meta["perm"] >= 0:
                await reply(update, MAINT_TEXT.get(gget(chat.id, "language", "en") if is_group(chat) else "en"))
            return
        if is_group(chat) and not group_enabled(chat.id):
            return
    if meta["perm"] == 6 and not is_owner:
        return await reply(update, "🚫 This command is restricted to the bot owner.")
    if not is_group(chat) and not meta["dm"]:
        return await reply(update, "👥 This command only works in groups.")
    if is_group(chat) and meta["perm"] > 0 and not is_owner:
        role = await get_role(ctx.bot, chat.id, user.id)
        if role < meta["perm"]:
            return await reply(update, f"🚫 You need <b>{ROLE_NAMES[meta['perm']]}</b> rank or higher to use /{name}.")
    try:
        await IMPL[meta["target"]](update, ctx, meta["target"])
    except RetryAfter as e:
        await asyncio.sleep(min(e.retry_after, 5))
    except (BadRequest, Forbidden) as e:
        log.warning("/%s Telegram error: %s", name, e)
        await reply(update, f"❌ Telegram rejected the request: <code>{h(e.message)}</code>")


def make_handler(name: str):
    async def handler(update: Update, ctx):
        await run_command(update, ctx, name)
    handler.__name__ = f"h_{name}"
    return handler


# =========================================
# SCHEDULED TASK RUNNER
# =========================================
async def send_payload(bot, chat_id: int, p: dict, pin: bool = False):
    if p.get("from_chat") and p.get("message_id"):
        m = await bot.copy_message(chat_id, p["from_chat"], p["message_id"])
        mid = m.message_id
    else:
        text, kb = split_buttons(p.get("text", ""))
        m = await say(bot, chat_id, "📢 <b>ANNOUNCEMENT</b>\n\n" + text, reply_markup=kb)
        mid = m.message_id
    if pin:
        try:
            await bot.pin_chat_message(chat_id, mid, disable_notification=False)
        except TelegramError:
            pass


async def run_task(tid: int):
    with db() as s:
        t = s.get(ScheduledTask, tid)
        if not t or t.done:
            return
        kind, gid, uid, payload = t.kind, t.group_id, t.user_id, json.loads(t.payload or "{}")
        t.done = True
    bot = APP.bot
    try:
        if kind == "unban":
            if (await bot.get_chat_member(gid, uid)).status == CMS.BANNED:
                await bot.unban_chat_member(gid, uid, only_if_banned=True)
                await alog(bot, gid, "UNBAN", 0, uid, "temporary ban expired")
        elif kind == "unmute":
            if (await bot.get_chat_member(gid, uid)).status == CMS.RESTRICTED:
                await restore_perms(bot, gid, uid)
                await alog(bot, gid, "UNMUTE", 0, uid, "temporary mute expired")
        elif kind == "raid_off":
            await set_raid(bot, gid, False)
        elif kind == "captcha_kick":
            with db() as s:
                v = s.execute(select(Verification).where(Verification.group_id == gid, Verification.user_id == uid)).scalar()
                pending = bool(v and not v.verified)
            if pending:
                await bot.ban_chat_member(gid, uid)
                await bot.unban_chat_member(gid, uid, only_if_banned=True)
                _UNVER.discard((gid, uid))
                with db() as s:
                    s.execute(delete(Verification).where(Verification.group_id == gid, Verification.user_id == uid))
                if payload.get("msg_id"):
                    try:
                        await bot.delete_message(gid, payload["msg_id"])
                    except TelegramError:
                        pass
                await alog(bot, gid, "KICK", 0, uid, "failed CAPTCHA (timeout)")
        elif kind == "announce":
            await send_payload(bot, gid, payload, payload.get("pin", False))
    except TelegramError as e:
        log.warning("Task %s (%s) failed: %s", tid, kind, e)


# =========================================
# GENERAL / COMMAND CENTER
# =========================================
CC_PAGE = 10


def uptime_str() -> str:
    return fmt_dur(time.time() - START_TIME)


def cc_home():
    rows, row = [], []
    for i, (emo, cat) in enumerate(CATEGORIES):
        row.append(Btn(f"{emo} {cat}", callback_data=f"cc:c:{i}:0"))
        if len(row) == 2:
            rows.append(row)
            row = []
    if row:
        rows.append(row)
    text = ("🤖 <b>IVY COMMAND CENTER</b>\n\nChoose a category:\n\n"
            f"<i>{len(META)} commands · search with</i> <code>/command ban</code>")
    return text, Kb(rows)


def cc_cat(i: int, page: int):
    emo, cat = CATEGORIES[i]
    items = list(COMMANDS[cat].items())
    pages = max(1, -(-len(items) // CC_PAGE))
    page = max(0, min(page, pages - 1))
    lines = [f"{emo} <b>{cat.upper()}</b>  <i>({page + 1}/{pages})</i>\n"]
    for n, d in items[page * CC_PAGE:(page + 1) * CC_PAGE]:
        lines.append(f"/{n} — {h(d['description'])}{' 👑' if d['permission'] == 'Bot Owner' else ''}")
    back = f"cc:c:{i}:{page - 1}" if page > 0 else "cc:home"
    nxt = f"cc:c:{i}:{min(page + 1, pages - 1)}"
    return "\n".join(lines), Kb([[Btn("⬅️ Back", callback_data=back), Btn("➡️ Next", callback_data=nxt),
                                  Btn("🏠 Home", callback_data="cc:home")]])


def command_info(name: str):
    name = name.lower().lstrip("/")
    m = META.get(name)
    if not m:
        near = [n for n in META if n.startswith(name[:3]) or name in n][:8]
        return "🔎 No such command." + (f" Did you mean: {', '.join('/' + n for n in near)}?" if near else "")
    usage = m["usage"]
    reply_usage = re.sub(r"@user(name)?\s*", "", usage) if "@user" in usage else None
    out = f"🔎 <b>COMMAND INFORMATION</b>\n\n/{m['name']}\n\n<b>Description:</b>\n{h(m['desc'])}\n\n" \
          f"<b>Usage:</b>\n<code>{h(META[m['target']]['usage'])}</code>\n\n"
    if reply_usage:
        out += f"<b>Reply usage:</b>\n<code>{h(reply_usage.strip())}</code>\n\n"
    return out + f"<b>Permission:</b>\n{ROLE_NAMES[m['perm']]}"


@impl("command")
async def cmd_command(update, ctx, name):
    if ctx.args:
        return await reply(update, command_info(ctx.args[0]))
    text, kb = cc_home()
    await reply(update, text, reply_markup=kb)


@impl("help")
async def cmd_help(update, ctx, name):
    text, kb = cc_home()
    await reply(update, "📖 <b>HELP</b>\nTap a category to browse commands. Reply-based usage works for most "
                        "moderation commands.\n\n" + text, reply_markup=kb)


async def send_rules_to(ctx, gid: int, chat_id: int):
    rules = gget(gid, "rules_text", "")
    if not rules:
        return await say(ctx.bot, chat_id, "📜 No rules have been set for this group yet.")
    text, kb = split_buttons(rules)
    await say(ctx.bot, chat_id, "📜 <b>RULES</b>\n\n" + text, reply_markup=kb)


@impl("start")
async def cmd_start(update, ctx, name):
    chat = update.effective_chat
    if ctx.args and ctx.args[0].startswith("rules_"):
        try:
            return await send_rules_to(ctx, int(ctx.args[0][6:]), chat.id)
        except ValueError:
            pass
    if is_group(chat):
        return await reply(update, f"👋 <b>{h(BOT_NAME)}</b> is active here. Use /command to see what I can do.")
    uname = ctx.bot.username
    kb = Kb([[Btn("➕ Add me to a group", url=f"https://t.me/{uname}?startgroup=true&admin=delete_messages+restrict_members+pin_messages+invite_users")],
             [Btn("📖 Commands", callback_data="cc:home")]])
    await reply(update, f"🛡️ <b>{h(BOT_NAME)}</b> — advanced group management.\n\nModeration, locks, anti-raid, "
                        f"CAPTCHA, filters, XP, economy and more.\n\nAdd me to a group, make me admin, then use /command.",
                reply_markup=kb)


@impl("about", "botinfo", "version", "features", "changelog", "support")
async def cmd_botinfo(update, ctx, name):
    if name == "version":
        return await reply(update, f"🤖 <b>{h(BOT_NAME)}</b> v{VERSION}")
    if name == "features":
        lines = [f"{e} {c}: {len(COMMANDS[c])} commands" for e, c in CATEGORIES]
        return await reply(update, f"✨ <b>FEATURES</b>\n\n" + "\n".join(lines) +
                           f"\n\nTotal: <b>{len(META)}</b> commands. Full list: /command")
    if name == "changelog":
        return await reply(update, f"📝 <b>CHANGELOG</b>\n\n<b>v{VERSION}</b>\n• First release: moderation, two-level locks, "
                                   "anti-spam/flood/raid, CAPTCHA, filters, notes, welcome, XP, economy, broadcast, owner panel.")
    if name == "support":
        kb = Kb([[Btn("💬 Support", url=SUPPORT_URL)]]) if SUPPORT_URL else None
        return await reply(update, "💬 Need help? Use /command for the command browser." +
                           ("" if SUPPORT_URL else "\nThe owner has not configured a support link (SUPPORT_URL)."), reply_markup=kb)
    await reply(update, f"🛡️ <b>{h(BOT_NAME)}</b> v{VERSION}\nGroup management &amp; moderation bot.\n"
                        f"Commands: <b>{len(META)}</b> · Uptime: {uptime_str()}\nBuilt with python-telegram-bot.")


@impl("ping")
async def cmd_ping(update, ctx, name):
    t0 = time.perf_counter()
    m = await reply(update, "🏓 Pong!")
    try:
        await m.edit_text(f"🏓 Pong! <code>{(time.perf_counter() - t0) * 1000:.0f} ms</code>", parse_mode=ParseMode.HTML)
    except TelegramError:
        pass


@impl("uptime")
async def cmd_uptime(update, ctx, name):
    await reply(update, f"⚡ Uptime: <b>{uptime_str()}</b>")


@impl("status")
async def cmd_status(update, ctx, name):
    chat = update.effective_chat
    if is_group(chat):
        tid, _ = await resolve_target(update, ctx)
        if tid:
            try:
                m = await ctx.bot.get_chat_member(chat.id, tid)
            except TelegramError as e:
                return await reply(update, f"❌ {h(e.message)}")
            role = await get_role(ctx.bot, chat.id, tid)
            extra = ""
            if m.status == CMS.RESTRICTED:
                extra = " (restricted" + (f" until {fmt_ts(m.until_date.timestamp(), chat.id)}" if m.until_date and m.until_date.year < 2100 else "") + ")"
            return await reply(update, f"👤 {mention(tid)}\nChat status: <b>{m.status}</b>{extra}\nRank: <b>{ROLE_NAMES[role]}</b>")
    state = "🟢 ONLINE" if bot_online() else "🔴 MAINTENANCE"
    await reply(update, f"{state}\n⚡ Uptime: {uptime_str()}\n🧩 Version: {VERSION}")


# =========================================
# MODERATION
# =========================================
RESTRICT_MAP = {"text": ["can_send_messages"],
                "media": ["can_send_audios", "can_send_documents", "can_send_photos", "can_send_videos",
                          "can_send_video_notes", "can_send_voice_notes"],
                "stickers": ["can_send_other_messages"], "gifs": ["can_send_other_messages"],
                "polls": ["can_send_polls"], "links": ["can_add_web_page_previews"],
                "info": ["can_change_info"], "invite": ["can_invite_users"], "pin": ["can_pin_messages"]}


@impl("ban", "unban", "tban", "kick", "softban", "mute", "unmute", "tmute", "restrict", "unrestrict")
async def cmd_mod(update, ctx, name):
    chat, me = update.effective_chat, update.effective_user
    tid, args = await resolve_target(update, ctx)
    if not tid:
        return await reply(update, f"Usage: <code>{h(META[name]['usage'])}</code>\n\n{NO_TARGET}")
    undo = name in ("unban", "unmute", "unrestrict")
    err = await safety(ctx, chat.id, me.id, tid, rank_check=not undo)
    if err:
        return await reply(update, err)
    secs = None
    if name in ("tban", "tmute") or (name == "mute" and args and parse_duration(args[0])):
        secs = parse_duration(args[0]) if args else None
        if not secs:
            return await reply(update, "⏱️ Give a duration such as <code>30m</code>, <code>2h</code>, <code>7d</code> (min 1m, max 365d).")
        args = args[1:]
    restrict_types = []
    if name == "restrict":
        restrict_types = [a.lower() for a in args if a.lower() in RESTRICT_MAP or a.lower() == "all"]
        if not restrict_types:
            return await reply(update, "Choose what to restrict: <code>text media stickers polls links info invite pin all</code>")
        args = []
    reason = " ".join(args) or "—"
    until = datetime.fromtimestamp(time.time() + secs, tz=timezone.utc) if secs else None
    bot, cid = ctx.bot, chat.id
    if name in ("ban", "tban"):
        await bot.ban_chat_member(cid, tid, until_date=until)
        act, verb = "BAN", "banned"
    elif name == "unban":
        await bot.unban_chat_member(cid, tid, only_if_banned=True)
        act, verb = "UNBAN", "unbanned"
    elif name == "kick":
        await bot.ban_chat_member(cid, tid)
        await bot.unban_chat_member(cid, tid, only_if_banned=True)
        act, verb = "KICK", "kicked"
    elif name == "softban":
        await bot.ban_chat_member(cid, tid, revoke_messages=True)
        await bot.unban_chat_member(cid, tid, only_if_banned=True)
        act, verb = "KICK", "softbanned (messages removed)"
    elif name in ("mute", "tmute"):
        await bot.restrict_chat_member(cid, tid, ChatPermissions.no_permissions(), until_date=until)
        act, verb = "MUTE", "muted"
    elif name == "restrict":
        base = (await bot.get_chat(cid)).permissions or ChatPermissions.all_permissions()
        kw = {k: v for k, v in base.to_dict().items() if v is not None}
        for t in restrict_types:
            for f in (sum(RESTRICT_MAP.values(), []) if t == "all" else RESTRICT_MAP[t]):
                kw[f] = False
        await bot.restrict_chat_member(cid, tid, ChatPermissions(**kw), use_independent_chat_permissions=True)
        act, verb, reason = "MUTE", "restricted", f"restricted: {', '.join(restrict_types)}"
    else:  # unmute / unrestrict
        await restore_perms(bot, cid, tid)
        act, verb = "UNMUTE", "unrestricted"
    _RC.pop((cid, tid), None)
    if secs:
        schedule_task("unban" if name == "tban" else "unmute", cid, tid, time.time() + secs)
    await alog(bot, cid, act, me.id, tid, reason + (f" [{fmt_dur(secs)}]" if secs else ""))
    out = f"✅ {mention(tid)} {verb}."
    if secs:
        out += f"\n⏱️ Duration: <b>{fmt_dur(secs)}</b>"
    if reason != "—" and not undo:
        out += f"\n📝 Reason: {h(reason)}"
    await reply(update, out)


# =========================================
# WARNINGS
# =========================================
async def apply_penalty(bot, chat_id: int, tid: int, action: str, minutes: int = 60) -> str:
    """Executes ban/kick/mute and returns a description. Raises TelegramError if rejected."""
    if action == "ban":
        await bot.ban_chat_member(chat_id, tid)
        return "banned"
    if action == "kick":
        await bot.ban_chat_member(chat_id, tid)
        await bot.unban_chat_member(chat_id, tid, only_if_banned=True)
        return "kicked"
    until = datetime.fromtimestamp(time.time() + minutes * 60, tz=timezone.utc)
    await bot.restrict_chat_member(chat_id, tid, ChatPermissions.no_permissions(), until_date=until)
    schedule_task("unmute", chat_id, tid, time.time() + minutes * 60)
    return f"muted for {fmt_dur(minutes * 60)}"


async def do_warn(bot, chat_id: int, tid: int, by: int, reason: str) -> str:
    with db() as s:
        w = Warning(group_id=chat_id, user_id=tid, by_id=by, reason=reason[:300], ts=time.time())
        s.add(w)
        s.flush()
        wid = w.id
    count, limit = db_count(Warning, Warning.group_id == chat_id, Warning.user_id == tid), gget(chat_id, "warn_limit")
    await alog(bot, chat_id, "WARN", by, tid, reason)
    out = f"⚠️ {mention(tid)} warned <b>({count}/{limit})</b>\n📝 {h(reason)}"
    if count >= limit:
        action = gget(chat_id, "warn_action")
        try:
            done = await apply_penalty(bot, chat_id, tid, action, gget(chat_id, "warn_mute_minutes"))
            with db() as s:
                s.execute(delete(Warning).where(Warning.group_id == chat_id, Warning.user_id == tid))
            await alog(bot, chat_id, {"ban": "BAN", "kick": "KICK"}.get(action, "MUTE"), by, tid, "warn limit reached")
            out += f"\n🚨 Limit reached — user {done}."
        except TelegramError as e:
            out += f"\n❌ Limit reached but Telegram rejected the {action}: {h(e.message)}"
    return out, wid


@impl("warn", "unwarn", "warnings", "resetwarns", "warnlimit", "warnaction")
async def cmd_warn(update, ctx, name):
    chat, me = update.effective_chat, update.effective_user
    if name == "warnlimit":
        if not ctx.args:
            return await reply(update, f"⚠️ Warn limit: <b>{gget(chat.id, 'warn_limit')}</b>")
        if not ctx.args[0].isdigit() or not 2 <= int(ctx.args[0]) <= 20:
            return await reply(update, "Give a number between 2 and 20.")
        gset(chat.id, "warn_limit", int(ctx.args[0]))
        await alog(ctx.bot, chat.id, "SECURITY", me.id, 0, f"warn_limit={ctx.args[0]}")
        return await reply(update, f"✅ Warn limit set to <b>{ctx.args[0]}</b>.")
    if name == "warnaction":
        if not ctx.args or ctx.args[0].lower() not in ("mute", "kick", "ban"):
            return await reply(update, f"Current action: <b>{gget(chat.id, 'warn_action')}</b>\nUsage: <code>/warnaction mute/kick/ban</code>")
        gset(chat.id, "warn_action", ctx.args[0].lower())
        return await reply(update, f"✅ At the limit users will be <b>{ctx.args[0].lower()}</b>.")
    tid, args = await resolve_target(update, ctx)
    if name == "warnings":
        role = await get_role(ctx.bot, chat.id, me.id)
        if not tid or (tid != me.id and role < 1):
            tid = me.id
    if not tid:
        return await reply(update, f"Usage: <code>{h(META[name]['usage'])}</code>\n\n{NO_TARGET}")
    if name == "warnings":
        with db() as s:
            rows = s.execute(select(Warning).where(Warning.group_id == chat.id, Warning.user_id == tid).order_by(Warning.ts)).scalars().all()
        if not rows:
            return await reply(update, f"✅ {mention(tid)} has no warnings.")
        lines = [f"⚠️ <b>Warnings for</b> {mention(tid)} ({len(rows)}/{gget(chat.id, 'warn_limit')})"]
        lines += [f"{i}. {h(w.reason or '—')} <i>({fmt_ts(w.ts, chat.id)})</i>" for i, w in enumerate(rows, 1)]
        return await reply(update, "\n".join(lines))
    err = await safety(ctx, chat.id, me.id, tid, rank_check=(name == "warn"))
    if err and name == "warn":
        return await reply(update, err)
    if name == "warn":
        out, wid = await do_warn(ctx.bot, chat.id, tid, me.id, " ".join(args) or "No reason given")
        return await reply(update, out, reply_markup=Kb([[Btn("🗑️ Remove warn", callback_data=f"uw:{chat.id}:{wid}")]]))
    with db() as s:
        if name == "unwarn":
            w = s.execute(select(Warning).where(Warning.group_id == chat.id, Warning.user_id == tid).order_by(Warning.ts.desc())).scalars().first()
            if not w:
                return await reply(update, "✅ Nothing to remove.")
            s.delete(w)
            act = "UNWARN"
        else:
            s.execute(delete(Warning).where(Warning.group_id == chat.id, Warning.user_id == tid))
            act = "UNWARN"
    await alog(ctx.bot, chat.id, act, me.id, tid, name)
    await reply(update, f"✅ Warning{'s' if name == 'resetwarns' else ''} removed for {mention(tid)}.")


# =========================================
# LOCK SYSTEM (member_locked / admin_locked stored separately)
# =========================================
LOCK_TYPES = ["links", "forward", "photo", "video", "document", "audio", "voice", "sticker", "gif",
              "animation", "poll", "contact", "location", "media", "messages"]
LOCK_ALIASES = {"link": "links", "forwards": "forward", "photos": "photo", "videos": "video", "documents": "document",
                "docs": "document", "stickers": "sticker", "gifs": "gif", "polls": "poll", "contacts": "contact",
                "locations": "location", "voices": "voice", "message": "messages", "text": "messages"}
_LC: dict[int, dict] = {}


def get_locks(gid: int) -> dict:
    if gid not in _LC:
        with db() as s:
            rows = s.execute(select(Lock).where(Lock.group_id == gid)).scalars().all()
        _LC[gid] = {r.lock_type: (r.member_locked, r.admin_locked) for r in rows}
    return _LC[gid]


def set_lock(gid: int, t: str, member=None, admin=None):
    with db() as s:
        row = s.execute(select(Lock).where(Lock.group_id == gid, Lock.lock_type == t)).scalar()
        if not row:
            row = Lock(group_id=gid, lock_type=t, member_locked=False, admin_locked=False)
            s.add(row)
        if member is not None:
            row.member_locked = member
        if admin is not None:
            row.admin_locked = admin
    _LC.pop(gid, None)


def locks_view(gid: int, back: bool = False):
    lk = get_locks(gid)
    lines = ["🔒 <b>LOCKS</b>", "<i>Tap a type to cycle: 🔓 open → 🔒 members → 🔐 members + admins</i>", ""]
    btns = []
    for t in LOCK_TYPES:
        m, a = lk.get(t, (False, False))
        lines.append(f"{t}: Member {'❌' if m else '✅'} · Admin {'❌' if a else '✅'}")
        btns.append(Btn(f"{'🔐' if a else '🔒' if m else '🔓'} {t}", callback_data=f"lk:{gid}:{t}"))
    rows = [btns[i:i + 3] for i in range(0, len(btns), 3)]
    if back:
        rows.append([Btn("⬅️ Back", callback_data=f"sp:{gid}:home")])
    return "\n".join(lines), Kb(rows)


@impl("lock", "unlock", "lockadmin", "unlockadmin", "locks")
async def cmd_lock(update, ctx, name):
    chat, me = update.effective_chat, update.effective_user
    if name == "locks":
        text, kb = locks_view(chat.id)
        if await get_role(ctx.bot, chat.id, me.id) < 2:
            kb = None
        return await reply(update, text, reply_markup=kb)
    types = []
    for a in ctx.args or []:
        a = LOCK_ALIASES.get(a.lower(), a.lower())
        if a == "all":
            types = list(LOCK_TYPES)
            break
        if a in LOCK_TYPES:
            types.append(a)
        else:
            return await reply(update, f"❓ Unknown lock type <code>{h(a)}</code>.\nTypes: <code>{' '.join(LOCK_TYPES)}</code> or <code>all</code>")
    if not types:
        return await reply(update, f"Usage: <code>{h(META[name]['usage'])}</code>\nTypes: <code>{' '.join(LOCK_TYPES)}</code>")
    if not await bot_can(ctx, chat.id, "can_delete_messages"):
        await reply(update, "⚠️ Locks are saved, but I need the “Delete messages” admin permission to enforce them.")
    for t in types:
        if name == "lock":
            set_lock(chat.id, t, member=True)
        elif name == "unlock":
            set_lock(chat.id, t, member=False, admin=False)
        elif name == "lockadmin":
            set_lock(chat.id, t, member=True, admin=True)
        else:
            set_lock(chat.id, t, admin=False)
        await alog(ctx.bot, chat.id, name.upper(), me.id, 0, t)
    lk = get_locks(chat.id)
    lines = [f"{'🔒' if name in ('lock', 'lockadmin') else '🔓'} <b>{name}</b> applied:"]
    for t in types:
        m, a = lk.get(t, (False, False))
        lines.append(f"<code>{t}</code>  Member → {'❌' if m else '✅'} · Admin → {'❌' if a else '✅'}")
    if gget(chat.id, "lock_owner_exempt"):
        lines.append("\n<i>The group owner is exempt from admin locks.</i>")
    await reply(update, "\n".join(lines))


def msg_types(m) -> set:
    t = {"messages"}
    ents = list(m.entities or []) + list(m.caption_entities or [])
    if any(e.type in ("url", "text_link") for e in ents):
        t.add("links")
    if getattr(m, "forward_origin", None):
        t.add("forward")
    if m.photo:
        t.update(("photo", "media"))
    if m.video or m.video_note:
        t.update(("video", "media"))
    if m.animation:
        t.update(("gif", "animation", "media"))
    elif m.document:
        t.update(("document", "media"))
    if m.audio:
        t.update(("audio", "media"))
    if m.voice:
        t.update(("voice", "media"))
    if m.sticker:
        t.add("sticker")
    if m.poll:
        t.add("poll")
    if m.contact:
        t.add("contact")
    if m.location or m.venue:
        t.add("location")
    return t


def log_type(m) -> str:
    for attr, t in (("photo", "photo"), ("video", "video"), ("video_note", "video"), ("animation", "gif"),
                    ("sticker", "sticker"), ("voice", "voice"), ("audio", "audio"), ("document", "document")):
        if getattr(m, attr, None):
            return t
    return "text" if m.text else "other"


# =========================================
# MESSAGE MANAGEMENT
# =========================================
_PURGE: dict = {}
MEDIA_TYPES = ("photo", "video", "gif", "document", "audio", "voice")


async def del_ids(bot, chat_id: int, ids: list[int]) -> None:
    ids = sorted(set(ids))
    for i in range(0, len(ids), 100):
        try:
            await bot.delete_messages(chat_id, ids[i:i + 100])
        except RetryAfter as e:
            await asyncio.sleep(e.retry_after)
        except TelegramError as e:
            log.info("delete_messages: %s", e)


@impl("del", "purge", "purgefrom", "purgeto", "clear", "delall", "delmedia", "deltext", "delsticker", "delphoto", "delvideo")
async def cmd_msg(update, ctx, name):
    chat, me, msg = update.effective_chat, update.effective_user, update.effective_message
    if not await bot_can(ctx, chat.id, "can_delete_messages"):
        return await reply(update, "❌ I need the “Delete messages” admin permission first.")
    r = msg.reply_to_message
    if name == "del":
        if not r:
            return await reply(update, "↩️ Reply to the message you want to delete.")
        await del_ids(ctx.bot, chat.id, [r.message_id, msg.message_id])
        return
    if name == "purge":
        if not r:
            return await reply(update, "↩️ Reply to the first message to purge.")
        ids = list(range(r.message_id, msg.message_id + 1))
    elif name == "purgefrom":
        if not r:
            return await reply(update, "↩️ Reply to the message where the purge should start.")
        _PURGE[(chat.id, me.id)] = r.message_id
        return await reply(update, "📍 Start marked. Reply to the last message with /purgeto.")
    elif name == "purgeto":
        start = _PURGE.pop((chat.id, me.id), None)
        if not r or not start:
            return await reply(update, "Use /purgefrom on the first message, then reply to the last one with /purgeto.")
        ids = list(range(min(start, r.message_id), max(start, r.message_id)) ) + [max(start, r.message_id), msg.message_id]
    elif name == "clear":
        n = int(ctx.args[0]) if ctx.args and ctx.args[0].isdigit() else 0
        if not 1 <= n <= 200:
            return await reply(update, "Usage: <code>/clear &lt;1-200&gt;</code>")
        ids = list(range(max(1, msg.message_id - n), msg.message_id + 1))
    else:  # history-based deletes (Bot API cannot read history, so we use messages we logged; 48h limit)
        tid, args = await resolve_target(update, ctx)
        if name == "delall" and not tid:
            return await reply(update, NO_TARGET)
        n = next((int(a) for a in args if a.isdigit()), 100)
        n = max(1, min(n, 500))
        types = {"delmedia": MEDIA_TYPES, "deltext": ("text",), "delsticker": ("sticker",),
                 "delphoto": ("photo",), "delvideo": ("video",)}.get(name)
        with db() as s:
            q = select(MsgLog.message_id).where(MsgLog.group_id == chat.id, MsgLog.ts > time.time() - 47 * 3600)
            if tid:
                q = q.where(MsgLog.user_id == tid)
            if types:
                q = q.where(MsgLog.mtype.in_(types))
            ids = list(s.execute(q.order_by(MsgLog.ts.desc()).limit(1000 if name == "delall" else n)).scalars())
        ids.append(msg.message_id)
    if len(ids) > 1001:
        return await reply(update, "⚠️ That range is too large (max 1000 messages at once).")
    await del_ids(ctx.bot, chat.id, ids)
    await alog(ctx.bot, chat.id, "SECURITY", me.id, 0, f"{name}: {len(ids)} ids")
    await notice(ctx.bot, chat.id, f"🧹 Deletion requested for up to <b>{len(ids)}</b> messages "
                                   "(Telegram only removes messages younger than 48h).", 6)


# =========================================
# SECURITY
# =========================================
SEC_KEYS = ["antispam", "antiflood", "antiraid", "antibot", "anticaps", "antiemoji", "antimention", "antilink",
            "antiforward", "antichannel", "antisticker", "antigif", "antimedia", "antinsfw", "captcha", "raidmode"]
TOGGLES = {k: k for k in SEC_KEYS}
TOGGLES.update({"adminmoderation": "adminmoderation", "adminprotect": "adminprotect", "autowarn": "auto_warn",
                "automute": "auto_mute", "autoban": "auto_ban", "autodelete": "auto_delete",
                "xpon": "xp", "xpoff": "xp"})
NUMERIC = {"antiflood": "flood_limit", "anticaps": "caps_percent", "antiemoji": "emoji_limit",
           "antimention": "mention_limit", "antiraid": "raid_threshold", "captcha": "captcha_timeout"}
NSFW_WORDS = ("porn", "xxx", "nsfw", "onlyfans", "nudes", "sex video", "hentai", "18+ video")
EMOJI_RE = re.compile("[\U0001F300-\U0001FAFF\u2600-\u27BF]")
_FLOOD: dict = {}
_LAST: dict = {}
_JOINS: dict = {}
_RECENT: dict = {}
_UNVER: set = set()


@impl(*sorted(set(TOGGLES) | {"xpon", "xpoff"}))
async def cmd_toggle(update, ctx, name):
    chat, me = update.effective_chat, update.effective_user
    key = TOGGLES[name]
    arg = (ctx.args[0].lower() if ctx.args else "")
    if name in ("xpon", "xpoff"):
        val = name == "xpon"
    elif arg in ("on", "off", "yes", "no", "enable", "disable"):
        val = arg in ("on", "yes", "enable")
    elif arg.isdigit() and name in NUMERIC:
        gset(chat.id, NUMERIC[name], int(arg))
        val = True
    elif not arg:
        extra = f"\nThreshold: <code>{gget(chat.id, NUMERIC[name])}</code>" if name in NUMERIC else ""
        return await reply(update, f"{'🟢' if gget(chat.id, key) else '🔴'} <b>{name}</b> is "
                                   f"{'ON' if gget(chat.id, key) else 'OFF'}{extra}\nUsage: <code>{h(META[name]['usage'])}</code>")
    else:
        return await reply(update, f"Usage: <code>{h(META[name]['usage'])}</code>")
    if name == "raidmode":
        await set_raid(ctx.bot, chat.id, val)
    else:
        gset(chat.id, key, val)
    await alog(ctx.bot, chat.id, "SECURITY", me.id, 0, f"{key}={'on' if val else 'off'}")
    note = ""
    if val and name in ("antispam", "antiflood", "anticaps", "antiemoji", "antimention", "antilink", "antiforward",
                        "antisticker", "antigif", "antimedia", "antinsfw", "antichannel") and \
            not await bot_can(ctx, chat.id, "can_delete_messages"):
        note = "\n⚠️ I need the “Delete messages” permission to enforce this."
    if name == "antinsfw" and val:
        note += "\nℹ️ This is a keyword filter only — I do not classify images."
    if name == "captcha" and val and not await bot_can(ctx, chat.id, "can_restrict_members"):
        note += "\n⚠️ I need the “Ban users” permission to restrict unverified members."
    await reply(update, f"{'🟢' if val else '🔴'} <b>{name}</b> {'enabled' if val else 'disabled'}.{note}")


async def set_raid(bot, gid: int, on: bool, auto: bool = False):
    gset(gid, "raidmode", on)
    if on:
        schedule_task("raid_off", gid, 0, time.time() + gget(gid, "raid_minutes") * 60)
        # restrict everyone who joined during the raid window
        for uid, ts in list(_RECENT.get(gid, {}).items()):
            if time.time() - ts < gget(gid, "raid_window") * 2:
                try:
                    await bot.restrict_chat_member(gid, uid, ChatPermissions.no_permissions())
                    _UNVER.add((gid, uid))
                except TelegramError:
                    pass
        if gget(gid, "raid_lockdown"):
            try:
                chat = await bot.get_chat(gid)
                gset(gid, "saved_perms", chat.permissions.to_dict() if chat.permissions else None)
                await bot.set_chat_permissions(gid, ChatPermissions.no_permissions())
            except TelegramError as e:
                log.warning("lockdown failed: %s", e)
        text = ("🚨 <b>RAID DETECTED</b>\n\nRapid joining activity detected.\n\n🔒 Protection mode activated. New members must "
                f"verify. Normal mode returns automatically in {gget(gid, 'raid_minutes')} min.") if auto else \
               "🚨 <b>RAID MODE ON</b>\n\n🔒 New members must verify."
        await say(bot, gid, text)
        await alog(bot, gid, "SECURITY", 0, 0, "raid mode ON" + (" (auto)" if auto else ""))
    else:
        saved = gget(gid, "saved_perms")
        if saved:
            try:
                await bot.set_chat_permissions(gid, ChatPermissions(**{k: v for k, v in saved.items() if v is not None}))
            except TelegramError as e:
                log.warning("restore perms failed: %s", e)
            gset(gid, "saved_perms", None)
        await say(bot, gid, "✅ <b>Raid mode off.</b> Normal protection restored.")
        await alog(bot, gid, "SECURITY", 0, 0, "raid mode OFF")


async def start_captcha(bot, gid: int, user):
    try:
        await bot.restrict_chat_member(gid, user.id, ChatPermissions.no_permissions())
    except TelegramError as e:
        log.info("captcha restrict failed in %s: %s", gid, e)
    lang = gget(gid, "language", "en")
    text = ("🔐 <b>HUMAN VERIFICATION</b>\n\n" + (f"{mention(user.id, user.full_name)}, please verify that you are human."
            if lang == "en" else f"{mention(user.id, user.full_name)}, कृपया सत्यापित करें कि आप इंसान हैं।"))
    m = await say(bot, gid, text, reply_markup=Kb([[Btn("✅ VERIFY", callback_data=f"vf:{gid}:{user.id}")]]))
    with db() as s:
        v = s.execute(select(Verification).where(Verification.group_id == gid, Verification.user_id == user.id)).scalar()
        if not v:
            v = Verification(group_id=gid, user_id=user.id)
            s.add(v)
        v.verified, v.msg_id, v.created = False, m.message_id, time.time()
    _UNVER.add((gid, user.id))
    schedule_task("captcha_kick", gid, user.id, time.time() + gget(gid, "captcha_timeout") * 60, {"msg_id": m.message_id})


async def send_welcome(ctx, chat, user):
    if not gget(chat.id, "welcome"):
        return
    tpl = gget(chat.id, "welcome_text", "") or "👋 Welcome {mention} to <b>{group}</b>!\nYou are member #{count}."
    try:
        count = await ctx.bot.get_chat_member_count(chat.id)
    except TelegramError:
        count = 0
    text, kb = split_buttons(render_tpl(tpl, user, chat, count))
    if gget(chat.id, "rules_text"):
        rb = Btn("📜 Rules", url=f"https://t.me/{ctx.bot.username}?start=rules_{chat.id}")
        kb = Kb(list(kb.inline_keyboard) + [[rb]]) if kb else Kb([[rb]])
    old = gget(chat.id, "last_welcome")
    m = await say(ctx.bot, chat.id, text, reply_markup=kb)
    if old:
        try:
            await ctx.bot.delete_message(chat.id, old)
        except TelegramError:
            pass
    gset(chat.id, "last_welcome", m.message_id)


@impl("verify", "unverify", "verification")
async def cmd_verify(update, ctx, name):
    chat, me = update.effective_chat, update.effective_user
    if name == "verification":
        with db() as s:
            pending = s.execute(select(Verification.user_id).where(Verification.group_id == chat.id, Verification.verified == False)).scalars().all()  # noqa: E712
            done = db_count(Verification, Verification.group_id == chat.id, Verification.verified == True)  # noqa: E712
        return await reply(update, f"🔐 <b>VERIFICATION</b>\nCAPTCHA: {'🟢' if gget(chat.id, 'captcha') else '🔴'} · timeout "
                                   f"{gget(chat.id, 'captcha_timeout')} min\nVerified: <b>{done}</b> · Pending: <b>{len(pending)}</b>\n"
                                   + ("\n".join(mention(u) for u in pending[:20]) if pending else ""))
    tid, _ = await resolve_target(update, ctx)
    if not tid:
        return await reply(update, NO_TARGET)
    if name == "verify":
        await restore_perms(ctx.bot, chat.id, tid)
        with db() as s:
            v = s.execute(select(Verification).where(Verification.group_id == chat.id, Verification.user_id == tid)).scalar()
            if not v:
                v = Verification(group_id=chat.id, user_id=tid, created=time.time())
                s.add(v)
            v.verified = True
        _UNVER.discard((chat.id, tid))
        await alog(ctx.bot, chat.id, "SECURITY", me.id, tid, "verified manually")
        return await reply(update, f"✅ {mention(tid)} verified.")
    err = await safety(ctx, chat.id, me.id, tid)
    if err:
        return await reply(update, err)

    class _U:  # minimal user shim for start_captcha
        id, full_name = tid, display(tid)
    await start_captcha(ctx.bot, chat.id, _U)
    await alog(ctx.bot, chat.id, "SECURITY", me.id, tid, "verification required again")


# =========================================
# FILTERS
# =========================================
_FC: dict[int, list] = {}


def get_filters(gid: int) -> list:
    if gid not in _FC:
        with db() as s:
            rows = s.execute(select(Filter).where(Filter.group_id == gid)).scalars().all()
        _FC[gid] = [dict(id=r.id, pattern=r.pattern, kind=r.kind, action=r.action, response=r.response) for r in rows]
    return _FC[gid]


def filter_match(f: dict, text: str) -> bool:
    p, k = f["pattern"], f["kind"]
    try:
        if k == "regex":
            return re.search(p, text, re.I) is not None
        if k == "exact":
            return text.strip() == p
        if k == "partial":
            return p.lower() in text.lower()
        return re.search(rf"(?<!\w){re.escape(p)}(?!\w)", text, re.I) is not None
    except re.error:
        return False


def add_filter(gid: int, uid: int, pattern: str, kind: str, action: str, response: str | None):
    with db() as s:
        old = s.execute(select(Filter).where(Filter.group_id == gid, Filter.pattern == pattern, Filter.kind == kind)).scalar()
        if old:
            old.action, old.response = action, response
        else:
            s.add(Filter(group_id=gid, pattern=pattern, kind=kind, action=action, response=response, created_by=uid))
    _FC.pop(gid, None)


def remove_filters(gid: int, pattern: str | None, kinds: tuple, actions: tuple | None) -> int:
    with db() as s:
        q = select(Filter).where(Filter.group_id == gid, Filter.kind.in_(kinds))
        if pattern is not None:
            q = q.where(func.lower(Filter.pattern) == pattern.lower())
        if actions:
            q = q.where(Filter.action.in_(actions))
        rows = s.execute(q).scalars().all()
        for r in rows:
            s.delete(r)
    _FC.pop(gid, None)
    return len(rows)


BLOCK_ACTIONS = ("block", "delete", "warn", "mute", "ban")


@impl("filter", "delfilter", "filters", "clearfilters", "blockword", "unblockword", "blockedwords", "regex", "delregex")
async def cmd_filter(update, ctx, name):
    chat, me, msg = update.effective_chat, update.effective_user, update.effective_message
    args = list(ctx.args or [])
    gid = chat.id
    if name == "filters":
        rows = [f for f in get_filters(gid) if f["action"] == "reply"]
        return await reply(update, "📝 <b>FILTERS</b>\n" + ("\n".join(f"• <code>{h(f['pattern'])}</code> ({f['kind']})" for f in rows[:60]) if rows else "None yet."))
    if name == "blockedwords":
        rows = [f for f in get_filters(gid) if f["action"] != "reply"]
        return await reply(update, "🚫 <b>BLOCKED</b>\n" + ("\n".join(f"• <code>{h(f['pattern'])}</code> ({f['kind']} → {f['action']})" for f in rows[:60]) if rows else "Nothing blocked."))
    if name == "clearfilters":
        n = remove_filters(gid, None, ("word", "partial", "exact"), ("reply",))
        await alog(ctx.bot, gid, "FILTER", me.id, 0, f"cleared {n} filters")
        return await reply(update, f"🗑️ Removed {n} filter(s).")
    if not args:
        return await reply(update, f"Usage: <code>{h(META[name]['usage'])}</code>")
    if name in ("delfilter", "unblockword", "delregex"):
        kinds = ("regex",) if name == "delregex" else ("word", "partial", "exact")
        actions = ("reply",) if name == "delfilter" else BLOCK_ACTIONS
        pat = " ".join(args)
        pat = pat.split(":", 1)[1] if ":" in pat and pat.split(":", 1)[0] in ("word", "partial", "exact") else pat
        n = remove_filters(gid, pat, kinds, actions)
        await alog(ctx.bot, gid, "FILTER", me.id, 0, f"removed {pat}")
        return await reply(update, f"🗑️ Removed {n} entr{'y' if n == 1 else 'ies'}." if n else "❓ Nothing matched.")
    if name == "filter":
        first = args[0]
        kind = "word"
        if ":" in first and first.split(":", 1)[0] in ("word", "partial", "exact", "regex"):
            kind, first = first.split(":", 1)
        response = " ".join(args[1:]) or ((msg.reply_to_message.text or msg.reply_to_message.caption) if msg.reply_to_message else "")
        if not response:
            return await reply(update, "Give a response text, or reply to the message that should be sent.")
        if kind == "regex" and (len(first) > 100 or not _valid_regex(first)):
            return await reply(update, "❌ Invalid or too long regex.")
        add_filter(gid, me.id, first, kind, "reply", response)
        await alog(ctx.bot, gid, "FILTER", me.id, 0, f"added {kind}:{first}")
        return await reply(update, f"✅ Filter added for <code>{h(first)}</code> ({kind}).")
    # blockword / regex
    pattern, action = args[0], "block"
    if name == "regex":
        pattern = " ".join(args)
        if args[-1].lower() in BLOCK_ACTIONS and len(args) > 1:
            action, pattern = args[-1].lower(), " ".join(args[:-1])
        if len(pattern) > 100 or not _valid_regex(pattern):
            return await reply(update, "❌ Invalid or too long regex (max 100 chars).")
    elif len(args) > 1 and args[1].lower() in BLOCK_ACTIONS:
        action = args[1].lower()
    add_filter(gid, me.id, pattern, "regex" if name == "regex" else "partial", action, None)
    await alog(ctx.bot, gid, "FILTER", me.id, 0, f"block {pattern} -> {action}")
    await reply(update, f"🚫 Blocking <code>{h(pattern)}</code> → <b>{action if action != 'block' else 'auto-action (see /autowarn, /automute, /autoban, /autodelete)'}</b>.")


def _valid_regex(p: str) -> bool:
    try:
        re.compile(p)
        return not re.search(r"(\([^)]*[+*][^)]*\))[+*]", p)  # reject obvious nested quantifiers (ReDoS)
    except re.error:
        return False


# =========================================
# MESSAGE HANDLERS (locks -> filters -> security -> stats/XP)
# =========================================
async def punish(ctx, chat, user, msg, reason: str, force: str | None = None):
    bot = ctx.bot
    action = force or ("ban" if gget(chat.id, "auto_ban") else "mute" if gget(chat.id, "auto_mute")
                       else "warn" if gget(chat.id, "auto_warn") else "delete" if gget(chat.id, "auto_delete") else "none")
    if (gget(chat.id, "auto_delete") or action in ("delete", "warn", "mute", "ban")) and msg:
        try:
            await msg.delete()
        except TelegramError:
            pass
    text = f"🚫 {mention(user.id, user.full_name)}: {h(reason)}"
    try:
        if action == "ban":
            await bot.ban_chat_member(chat.id, user.id)
            await alog(bot, chat.id, "BAN", 0, user.id, f"auto: {reason}")
            text += " → banned"
        elif action == "mute":
            done = await apply_penalty(bot, chat.id, user.id, "mute", gget(chat.id, "auto_mute_minutes"))
            await alog(bot, chat.id, "MUTE", 0, user.id, f"auto: {reason}")
            text += f" → {done}"
        elif action == "warn":
            out, _ = await do_warn(bot, chat.id, user.id, bot.id, f"auto: {reason}")
            text = out
    except TelegramError as e:
        text += f" (couldn't punish: {h(e.message)})"
    await notice(bot, chat.id, text, 12)


def detect_violations(msg, chat, uid: int, text: str, types: set) -> list[str]:
    gid, v, now = chat.id, [], time.time()
    if gget(gid, "antiflood"):
        dq = _FLOOD.setdefault((gid, uid), deque())
        dq.append(now)
        while dq and now - dq[0] > gget(gid, "flood_window"):
            dq.popleft()
        if len(dq) > gget(gid, "flood_limit"):
            dq.clear()
            v.append("flooding")
    if gget(gid, "antispam") and text:
        dq = _LAST.setdefault((gid, uid), deque(maxlen=4))
        sig = hashlib.md5(text.strip().lower().encode()).hexdigest()
        dq.append((sig, now))
        if sum(1 for s_, t_ in dq if s_ == sig and now - t_ < 30) >= 3:
            dq.clear()
            v.append("repeated messages")
    letters = [c for c in text if c.isalpha()]
    if gget(gid, "anticaps") and len(letters) >= gget(gid, "caps_min") and \
            sum(c.isupper() for c in letters) * 100 // len(letters) >= gget(gid, "caps_percent"):
        v.append("excessive caps")
    if gget(gid, "antiemoji") and len(EMOJI_RE.findall(text)) > gget(gid, "emoji_limit"):
        v.append("emoji spam")
    if gget(gid, "antimention"):
        ments = sum(1 for e in list(msg.entities or []) + list(msg.caption_entities or []) if e.type in ("mention", "text_mention"))
        if ments > gget(gid, "mention_limit"):
            v.append("mention spam")
    if gget(gid, "antilink") and "links" in types:
        v.append("links not allowed")
    if gget(gid, "antiforward") and "forward" in types:
        v.append("forwards not allowed")
    if gget(gid, "antisticker") and "sticker" in types:
        v.append("stickers not allowed")
    if gget(gid, "antigif") and "gif" in types:
        v.append("GIFs not allowed")
    if gget(gid, "antimedia") and "media" in types:
        v.append("media not allowed")
    if gget(gid, "antinsfw") and text and any(w in text.lower() for w in NSFW_WORDS):
        v.append("NSFW keywords")
    if gget(gid, "raidmode") and "links" in types and now - _RECENT.get(gid, {}).get(uid, 0) < gget(gid, "raid_minutes") * 60:
        v.append("link from a new member during a raid")
    return v


async def on_message(update: Update, ctx):
    msg, chat, user = update.effective_message, update.effective_chat, update.effective_user
    if not msg or not chat:
        return
    if chat.type == ChatType.PRIVATE:
        if user:
            track(update)
        return
    if not is_group(chat) or msg.is_automatic_forward:
        return
    is_owner = bool(user and user.id == OWNER_ID and OWNER_ID)
    if not is_owner and (not bot_online() or not group_enabled(chat.id)):
        return
    edited = update.edited_message is not None
    track(update)
    gid = chat.id
    text = msg.text or msg.caption or ""
    prefix = gget(gid, "prefix", "")
    if prefix and msg.text and msg.text.startswith(prefix) and not edited:
        parts = msg.text[len(prefix):].split()
        if parts and parts[0].lower() in META:
            ctx.args = parts[1:]
            return await run_command(update, ctx, parts[0].lower())
    # sender resolution
    if msg.sender_chat and msg.sender_chat.id != gid:  # channel identity
        if gget(gid, "antichannel"):
            try:
                await msg.delete()
            except TelegramError:
                pass
        return
    if not user or user.is_bot or msg.sender_chat:
        return
    uid, types = user.id, msg_types(msg)
    if (gid, uid) in _UNVER:
        try:
            await msg.delete()
        except TelegramError:
            pass
        return
    role_cache: dict = {}

    async def role() -> int:
        if "r" not in role_cache:
            role_cache["r"] = await get_role(ctx.bot, gid, uid)
        return role_cache["r"]

    # 1) locks
    locks = get_locks(gid)
    hit = [t for t in types if t in locks and (locks[t][0] or locks[t][1])]
    if hit:
        r = await role()
        exempt = r >= 4 and gget(gid, "lock_owner_exempt")
        locked = [t for t in hit if (locks[t][1] if r >= 2 else locks[t][0])]
        if locked and not exempt:
            try:
                await msg.delete()
            except TelegramError:
                pass
            await notice(ctx.bot, gid, f"🔒 {mention(uid, user.full_name)}: <b>{h(locked[0])}</b> is locked here.", 6)
            return
    # 2) notes shortcut, filters
    if text.startswith("#") and 1 < len(text) < 50 and not edited:
        await send_note(ctx, gid, text[1:].split()[0].lower(), msg)
    if gget(gid, "filters_on") and text:
        for f in get_filters(gid):
            if not filter_match(f, text):
                continue
            if f["action"] == "reply":
                if not edited:
                    try:
                        body, kb = split_buttons(f["response"] or "")
                        await say(ctx.bot, gid, render_tpl(body, user, chat, 0), reply_markup=kb, reply_to_message_id=msg.message_id)
                    except TelegramError:
                        pass
                continue
            r = await role()
            if r >= 2 and not gget(gid, "adminmoderation"):
                break
            await punish(ctx, chat, user, msg, f"blocked content ({f['pattern'][:30]})", None if f["action"] == "block" else f["action"])
            return
    # 3) security
    viol = detect_violations(msg, chat, uid, text, types)
    if viol:
        r = await role()
        if r < 2 or gget(gid, "adminmoderation"):
            await punish(ctx, chat, user, msg, viol[0])
            return
    if edited:
        return
    # 4) statistics + XP
    with db() as s:
        s.add(MsgLog(group_id=gid, message_id=msg.message_id, user_id=uid, mtype=log_type(msg), ts=time.time()))
    _bump(gid, uid)
    await xp_tick(ctx, chat, user)


_MC: dict = {}
_ML_N = [0]


def _bump(gid: int, uid: int):
    _MC[(gid, uid)] = _MC.get((gid, uid), 0) + 1
    _ML_N[0] += 1
    if _ML_N[0] % 200 == 0:
        with db() as s:
            s.execute(delete(MsgLog).where(MsgLog.ts < time.time() - 48 * 3600))


def flush_counters():
    if not _MC:
        return
    items = list(_MC.items())
    _MC.clear()
    with db() as s:
        for (gid, uid), n in items:
            row = s.execute(select(XP).where(XP.group_id == gid, XP.user_id == uid)).scalar()
            if not row:
                row = XP(group_id=gid, user_id=uid, xp=0, level=0, messages=0)
                s.add(row)
                s.flush()
            row.messages = (row.messages or 0) + n


async def on_new_members(update: Update, ctx):
    msg, chat = update.effective_message, update.effective_chat
    if not is_group(chat):
        return
    track(update)
    if not bot_online() or not group_enabled(chat.id):
        return
    gid, adder = chat.id, msg.from_user
    for m in msg.new_chat_members:
        if m.id == ctx.bot.id:
            continue
        upsert_user(m)
        with db() as s:
            s.add(JoinLog(group_id=gid, user_id=m.id, event="join", ts=time.time()))
        if m.is_bot and gget(gid, "antibot") and (not adder or adder.id == m.id or await get_role(ctx.bot, gid, adder.id) < 2):
            try:
                await ctx.bot.ban_chat_member(gid, m.id)
                await alog(ctx.bot, gid, "BAN", 0, m.id, "anti-bot: bot added by non-admin")
                await notice(ctx.bot, gid, f"🤖 Bot {mention(m.id, m.full_name)} removed (anti-bot).", 10)
            except TelegramError:
                pass
            continue
        now = time.time()
        _RECENT.setdefault(gid, {})[m.id] = now
        dq = _JOINS.setdefault(gid, deque())
        dq.append(now)
        while dq and now - dq[0] > gget(gid, "raid_window"):
            dq.popleft()
        if gget(gid, "antiraid") and not gget(gid, "raidmode") and len(dq) >= gget(gid, "raid_threshold"):
            await set_raid(ctx.bot, gid, True, auto=True)
        if not m.is_bot and (gget(gid, "captcha") or gget(gid, "raidmode")):
            await start_captcha(ctx.bot, gid, m)
        elif not m.is_bot:
            await send_welcome(ctx, chat, m)
    if gget(gid, "clean_service"):
        try:
            await msg.delete()
        except TelegramError:
            pass


async def on_left_member(update: Update, ctx):
    msg, chat = update.effective_message, update.effective_chat
    if not is_group(chat) or not bot_online() or not group_enabled(chat.id):
        return
    u = msg.left_chat_member
    if not u or u.id == ctx.bot.id:
        return
    with db() as s:
        s.add(JoinLog(group_id=chat.id, user_id=u.id, event="leave", ts=time.time()))
    if gget(chat.id, "goodbye") and not u.is_bot:
        tpl = gget(chat.id, "goodbye_text", "") or "👋 Goodbye {user}!"
        text, kb = split_buttons(render_tpl(tpl, u, chat, 0))
        await say(ctx.bot, chat.id, text, reply_markup=kb)
    if gget(chat.id, "clean_service"):
        try:
            await msg.delete()
        except TelegramError:
            pass


async def on_my_chat_member(update: Update, ctx):
    ev = update.my_chat_member
    chat = ev.chat
    if not is_group(chat):
        return
    new, old = ev.new_chat_member.status, ev.old_chat_member.status
    with db() as s:
        g = s.get(Group, chat.id)
        if not g:
            g = Group(group_id=chat.id, added_ts=time.time())
            s.add(g)
        g.title, g.username = chat.title, chat.username
        g.left = new in (CMS.LEFT, CMS.BANNED)
    if new in (CMS.MEMBER, CMS.ADMINISTRATOR) and old in (CMS.LEFT, CMS.BANNED):
        await say(ctx.bot, chat.id, f"🛡️ <b>{h(BOT_NAME)}</b> is here! Please make me an admin with <i>Delete messages, "
                                    "Ban users, Pin messages</i> permissions, then use /settings and /command.")


# =========================================
# WELCOME / GOODBYE / RULES
# =========================================
def _text_arg(update, ctx) -> str:
    msg = update.effective_message
    body = msg.text or ""
    parts = body.split(None, 1)
    inline = parts[1] if len(parts) > 1 else ""
    if inline:
        return inline
    r = msg.reply_to_message
    return (r.text_html or r.caption_html or "") if r else ""


def _inline_html(update) -> str:
    """Keep the person's formatting: use HTML of the inline text via entities."""
    msg = update.effective_message
    if msg.text_html and " " in msg.text.strip():
        return msg.text_html.split(None, 1)[1] if len(msg.text_html.split(None, 1)) > 1 else ""
    return ""


@impl("welcome", "setwelcome", "delwelcome", "goodbye", "setgoodbye", "delgoodbye", "newmembers", "membercount", "joinstats")
async def cmd_welcome(update, ctx, name):
    chat, me = update.effective_chat, update.effective_user
    gid = chat.id
    if name == "membercount":
        return await reply(update, f"👥 Members: <b>{await ctx.bot.get_chat_member_count(gid)}</b>")
    if name in ("newmembers", "joinstats"):
        now = time.time()
        with db() as s:
            def cnt(ev, secs):
                return s.execute(select(func.count()).select_from(JoinLog).where(JoinLog.group_id == gid, JoinLog.event == ev, JoinLog.ts > now - secs)).scalar()
            if name == "joinstats":
                return await reply(update, "📈 <b>JOIN STATS</b>\n" + "\n".join(
                    f"{lbl}: +{cnt('join', sec)} / −{cnt('leave', sec)}" for lbl, sec in (("24h", 86400), ("7d", 7 * 86400), ("30d", 30 * 86400))))
            ids = s.execute(select(JoinLog.user_id).where(JoinLog.group_id == gid, JoinLog.event == "join", JoinLog.ts > now - 86400).order_by(JoinLog.ts.desc()).limit(30)).scalars().all()
        return await reply(update, f"🆕 <b>NEW MEMBERS (24h)</b>: {len(ids)}\n" + ("\n".join(mention(u) for u in ids) if ids else "None."))
    kind = "goodbye" if "goodbye" in name else "welcome"
    if name in ("welcome", "goodbye"):
        arg = (ctx.args[0].lower() if ctx.args else "")
        if arg in ("on", "off"):
            gset(gid, kind, arg == "on")
            return await reply(update, f"{'🟢' if arg == 'on' else '🔴'} {kind.title()} {'enabled' if arg == 'on' else 'disabled'}.")
        tpl = gget(gid, f"{kind}_text", "") or ("👋 Welcome {mention} to <b>{group}</b>!\nYou are member #{count}." if kind == "welcome" else "👋 Goodbye {user}!")
        if arg == "preview":
            text, kb = split_buttons(render_tpl(tpl, update.effective_user, chat, 0))
            return await reply(update, text, reply_markup=kb)
        return await reply(update, f"{'🟢' if gget(gid, kind) else '🔴'} <b>{kind.title()}</b>\n\n<code>{h(tpl)}</code>\n\n"
                                   f"Variables: <code>{{user}} {{username}} {{mention}} {{id}} {{group}} {{count}}</code>\n"
                                   "Buttons: <code>{button:Text|https://url}</code>\nUsage: <code>/" + name + " on/off/preview</code>")
    if name.startswith("set"):
        text = _inline_html(update) or _text_arg(update, ctx)
        if not text:
            return await reply(update, f"Usage: <code>/{name} &lt;text&gt;</code> or reply to a message. Variables: "
                                       "<code>{user} {username} {mention} {id} {group} {count}</code>")
        gset(gid, f"{kind}_text", text)
        gset(gid, kind, True)
        return await reply(update, f"✅ {kind.title()} message saved and enabled. Preview: /{kind} preview")
    gset(gid, f"{kind}_text", "")
    gset(gid, kind, False)
    await reply(update, f"🗑️ Custom {kind} message removed and {kind} disabled.")


@impl("setrules", "rules", "delrules")
async def cmd_rules(update, ctx, name):
    gid = update.effective_chat.id
    if name == "rules":
        return await send_rules_to(ctx, gid, gid)
    if name == "delrules":
        gset(gid, "rules_text", "")
        return await reply(update, "🗑️ Rules deleted.")
    text = _inline_html(update) or _text_arg(update, ctx)
    if not text:
        return await reply(update, "Usage: <code>/setrules &lt;text&gt;</code> or reply to a message. Buttons: <code>{button:Text|https://url}</code>")
    gset(gid, "rules_text", text)
    await reply(update, "✅ Rules saved. Show them with /rules")


# =========================================
# NOTES
# =========================================
MEDIA_SEND = {"photo": "send_photo", "video": "send_video", "document": "send_document", "sticker": "send_sticker",
              "animation": "send_animation", "audio": "send_audio", "voice": "send_voice"}


async def send_note(ctx, gid: int, nm: str, msg=None):
    with db() as s:
        n = s.execute(select(Note).where(Note.group_id == gid, Note.name == nm)).scalar()
    if not n:
        return False
    kw = {"reply_to_message_id": msg.message_id} if msg else {}
    try:
        if n.media_type:
            body, kb = split_buttons(n.text or "")
            fn = getattr(ctx.bot, MEDIA_SEND[n.media_type])
            arg = {"caption": body, "parse_mode": ParseMode.HTML} if n.media_type != "sticker" else {}
            await fn(gid, n.file_id, reply_markup=kb, **arg, **kw)
        else:
            body, kb = split_buttons(n.text or "")
            await say(ctx.bot, gid, body, reply_markup=kb, **kw)
    except BadRequest:
        await say(ctx.bot, gid, "❌ Couldn't send that note (invalid formatting or media).")
    return True


@impl("save", "get", "notes", "delnote", "clearnotes")
async def cmd_notes(update, ctx, name):
    chat, msg = update.effective_chat, update.effective_message
    gid, args = chat.id, list(ctx.args or [])
    if name == "notes":
        with db() as s:
            names = s.execute(select(Note.name).where(Note.group_id == gid).order_by(Note.name)).scalars().all()
        return await reply(update, "📝 <b>NOTES</b>\n" + ("\n".join(f"• <code>#{n}</code>" for n in names[:80]) if names else "None yet. Use /save <name>"))
    if name == "clearnotes":
        with db() as s:
            s.execute(delete(Note).where(Note.group_id == gid))
        return await reply(update, "🗑️ All notes deleted.")
    if not args:
        return await reply(update, f"Usage: <code>{h(META[name]['usage'])}</code>")
    nm = args[0].lower().lstrip("#")
    if name == "get":
        if not await send_note(ctx, gid, nm, msg):
            await reply(update, f"❓ No note named <code>{h(nm)}</code>.")
        return
    if name == "delnote":
        with db() as s:
            row = s.execute(select(Note).where(Note.group_id == gid, Note.name == nm)).scalar()
            if row:
                s.delete(row)
        return await reply(update, "🗑️ Note deleted." if row else "❓ No such note.")
    text = " ".join(args[1:])
    mt = fid = None
    r = msg.reply_to_message
    if r:
        text = text or r.caption_html or r.text_html or ""
        for attr in MEDIA_SEND:
            obj = getattr(r, attr, None)
            if obj:
                mt, fid = attr, (obj[-1].file_id if attr == "photo" else obj.file_id)
                break
    if not text and not fid:
        return await reply(update, "Give the note content, or reply to a message.")
    with db() as s:
        row = s.execute(select(Note).where(Note.group_id == gid, Note.name == nm)).scalar()
        if not row:
            row = Note(group_id=gid, name=nm)
            s.add(row)
        row.text, row.media_type, row.file_id = text, mt, fid
    await reply(update, f"✅ Saved. Get it with <code>/get {h(nm)}</code> or <code>#{h(nm)}</code>")


# =========================================
# XP / ECONOMY
# =========================================
def level_for(xp: int) -> int:
    return int((xp / 100) ** 0.5)


def reward_for(gid: int, lvl: int) -> int:
    custom = gget(gid, "level_rewards", {}) or {}
    return int(custom.get(str(lvl), lvl * 50))


def _xp_row(s, gid, uid):
    row = s.execute(select(XP).where(XP.group_id == gid, XP.user_id == uid)).scalar()
    if not row:
        row = XP(group_id=gid, user_id=uid, xp=0, level=0, messages=0, last_xp=0)
        s.add(row)
        s.flush()
    return row


def _eco_row(s, gid, uid):
    row = s.execute(select(Economy).where(Economy.group_id == gid, Economy.user_id == uid)).scalar()
    if not row:
        row = Economy(group_id=gid, user_id=uid, coins=0)
        s.add(row)
        s.flush()
    return row


async def xp_tick(ctx, chat, user):
    gid = chat.id
    if not gget(gid, "xp"):
        return
    up = None
    with db() as s:
        row = _xp_row(s, gid, user.id)
        if time.time() - (row.last_xp or 0) < gget(gid, "xp_cooldown"):
            return
        row.xp += random.randint(15, 25)
        row.last_xp = time.time()
        new = level_for(row.xp)
        if new > row.level:
            row.level = new
            coins = reward_for(gid, new) if gget(gid, "economy") else 0
            if coins:
                _eco_row(s, gid, user.id).coins += coins
            up = (new, coins)
    if up and gget(gid, "xp_announce"):
        await notice(ctx.bot, gid, f"🎉 {mention(user.id, user.full_name)} reached <b>level {up[0]}</b>!"
                                   + (f" +{up[1]} 🪙" if up[1] else ""), 20)


async def _target_or_self(update, ctx):
    tid, args = await resolve_target(update, ctx)
    return tid or update.effective_user.id, args


@impl("rank", "setxp", "resetxp", "levels", "leaderboard", "rewards")
async def cmd_xp(update, ctx, name):
    chat, me = update.effective_chat, update.effective_user
    gid = chat.id
    flush_counters()
    if name == "levels":
        return await reply(update, "📶 <b>LEVELS</b>\n" + "\n".join(f"Level {l}: {l * l * 100} XP" for l in range(1, 11)) + "\n<i>XP needed = 100 × level²</i>")
    if name == "leaderboard":
        with db() as s:
            rows = s.execute(select(XP).where(XP.group_id == gid, XP.xp > 0).order_by(XP.xp.desc()).limit(10)).scalars().all()
        medals = ["🥇", "🥈", "🥉"] + ["▫️"] * 7
        return await reply(update, "🏆 <b>XP LEADERBOARD</b>\n" + ("\n".join(f"{medals[i]} {mention(r.user_id)} — L{r.level} · {r.xp} XP" for i, r in enumerate(rows)) or "No XP yet."))
    if name == "rewards":
        args = ctx.args or []
        if args and args[0] == "set":
            if await get_role(ctx.bot, gid, me.id) < 2:
                return await reply(update, "🚫 Admins only.")
            if len(args) != 3 or not args[1].isdigit() or not args[2].isdigit():
                return await reply(update, "Usage: <code>/rewards set &lt;level&gt; &lt;coins&gt;</code>")
            d = dict(gget(gid, "level_rewards", {}) or {})
            d[args[1]] = int(args[2])
            gset(gid, "level_rewards", d)
            return await reply(update, f"✅ Level {args[1]} now rewards {args[2]} 🪙")
        return await reply(update, "🎁 <b>LEVEL REWARDS</b> (coins)\n" + "\n".join(f"Level {l}: {reward_for(gid, l)} 🪙" for l in range(1, 11)) +
                           ("" if gget(gid, "economy") else "\n<i>Economy is off — rewards are paused.</i>"))
    if name == "rank":
        tid, _ = await _target_or_self(update, ctx)
        with db() as s:
            row = _xp_row(s, gid, tid)
            pos = 1 + s.execute(select(func.count()).select_from(XP).where(XP.group_id == gid, XP.xp > row.xp)).scalar()
        nxt = (row.level + 1) ** 2 * 100
        return await reply(update, f"⭐ <b>RANK</b> — {mention(tid)}\nLevel <b>{row.level}</b> · {row.xp}/{nxt} XP · #{pos}\nMessages: {row.messages}")
    tid, args = await resolve_target(update, ctx)
    if name == "setxp":
        if not tid or not args or not args[0].isdigit():
            return await reply(update, "Usage: <code>/setxp @user &lt;amount&gt;</code>")
        with db() as s:
            row = _xp_row(s, gid, tid)
            row.xp, row.level = int(args[0]), level_for(int(args[0]))
        return await reply(update, f"✅ {mention(tid)} now has {args[0]} XP.")
    with db() as s:  # resetxp
        if ctx.args and ctx.args[0].lower() == "all":
            s.execute(delete(XP).where(XP.group_id == gid))
            return await reply(update, "🗑️ XP reset for everyone.")
        if not tid:
            return await reply(update, "Usage: <code>/resetxp @user</code> or <code>/resetxp all</code>")
        row = _xp_row(s, gid, tid)
        row.xp = row.level = 0
    await reply(update, f"🗑️ XP reset for {mention(tid)}.")


@impl("balance", "daily", "weekly", "monthly", "pay", "economy", "rich", "shop", "buy")
async def cmd_eco(update, ctx, name):
    chat, me = update.effective_chat, update.effective_user
    gid, args = chat.id, list(ctx.args or [])
    if name == "economy":
        if args and await get_role(ctx.bot, gid, me.id) >= 2:
            if args[0].lower() in ("on", "off"):
                gset(gid, "economy", args[0].lower() == "on")
            elif args[0] in ("daily", "weekly", "monthly") and len(args) > 1 and args[1].isdigit():
                gset(gid, f"{args[0]}_amount", int(args[1]))
        return await reply(update, f"💰 <b>ECONOMY</b> {'🟢' if gget(gid, 'economy') else '🔴'}\nDaily {gget(gid, 'daily_amount')} · "
                                   f"Weekly {gget(gid, 'weekly_amount')} · Monthly {gget(gid, 'monthly_amount')} 🪙\n"
                                   "Admins: <code>/economy on/off</code> · <code>/economy daily 150</code>")
    if not gget(gid, "economy"):
        return await reply(update, "💤 The economy is disabled in this group.")
    if name in ("daily", "weekly", "monthly"):
        cd = {"daily": 86400, "weekly": 7 * 86400, "monthly": 30 * 86400}[name]
        amt = gget(gid, f"{name}_amount")
        with db() as s:
            row = _eco_row(s, gid, me.id)
            last = getattr(row, f"last_{name}") or 0
            if time.time() - last < cd:
                return await reply(update, f"⏳ Come back in <b>{fmt_dur(cd - (time.time() - last))}</b>.")
            row.coins += amt
            setattr(row, f"last_{name}", time.time())
            bal = row.coins
        return await reply(update, f"🎁 {name.title()} reward: <b>+{amt}</b> 🪙 — balance <b>{bal}</b>")
    if name == "balance":
        tid, _ = await _target_or_self(update, ctx)
        with db() as s:
            bal = _eco_row(s, gid, tid).coins
            items = s.execute(select(Inventory.item).where(Inventory.group_id == gid, Inventory.user_id == tid)).scalars().all()
        return await reply(update, f"💰 {mention(tid)}: <b>{bal}</b> 🪙" + (f"\n🎒 {h(', '.join(items))}" if items else ""))
    if name == "rich":
        with db() as s:
            rows = s.execute(select(Economy).where(Economy.group_id == gid, Economy.coins > 0).order_by(Economy.coins.desc()).limit(10)).scalars().all()
        return await reply(update, "🤑 <b>RICHEST</b>\n" + ("\n".join(f"{i}. {mention(r.user_id)} — {r.coins} 🪙" for i, r in enumerate(rows, 1)) or "Nobody yet."))
    if name == "pay":
        tid, rest = await resolve_target(update, ctx)
        if not tid or not rest or not rest[0].isdigit() or int(rest[0]) <= 0:
            return await reply(update, "Usage: <code>/pay @user &lt;amount&gt;</code>")
        amt = int(rest[0])
        if tid == me.id or tid == ctx.bot.id:
            return await reply(update, "🙅 Pick someone else.")
        with db() as s:
            a, b = _eco_row(s, gid, me.id), _eco_row(s, gid, tid)
            if a.coins < amt:
                return await reply(update, f"❌ You only have {a.coins} 🪙.")
            a.coins -= amt
            b.coins += amt
        return await reply(update, f"💸 {mention(me.id)} sent <b>{amt}</b> 🪙 to {mention(tid)}.")
    if name == "shop":
        if args and args[0].lower() in ("add", "remove"):
            if await get_role(ctx.bot, gid, me.id) < 2:
                return await reply(update, "🚫 Admins only.")
            if args[0].lower() == "add":
                if len(args) < 3 or not args[2].isdigit():
                    return await reply(update, "Usage: <code>/shop add &lt;name&gt; &lt;price&gt; [description]</code>")
                with db() as s:
                    s.add(ShopItem(group_id=gid, name=args[1].lower(), price=int(args[2]), description=" ".join(args[3:])))
                return await reply(update, "✅ Item added.")
            with db() as s:
                s.execute(delete(ShopItem).where(ShopItem.group_id == gid, ShopItem.name == (args[1].lower() if len(args) > 1 else "")))
            return await reply(update, "🗑️ Item removed.")
        with db() as s:
            items = s.execute(select(ShopItem).where(ShopItem.group_id == gid).order_by(ShopItem.price)).scalars().all()
        return await reply(update, "🛒 <b>SHOP</b>\n" + ("\n".join(f"• <b>{h(i.name)}</b> — {i.price} 🪙 {h(i.description or '')}" for i in items) or "Empty. Admins: /shop add") + "\nBuy with /buy &lt;name&gt;")
    if not args:  # buy
        return await reply(update, "Usage: <code>/buy &lt;item&gt;</code>")
    with db() as s:
        item = s.execute(select(ShopItem).where(ShopItem.group_id == gid, ShopItem.name == args[0].lower())).scalar()
        if not item:
            return await reply(update, "❓ No such item. See /shop")
        row = _eco_row(s, gid, me.id)
        if row.coins < item.price:
            return await reply(update, f"❌ You need {item.price} 🪙 (you have {row.coins}).")
        row.coins -= item.price
        s.add(Inventory(group_id=gid, user_id=me.id, item=item.name))
    await reply(update, f"🛍️ Bought <b>{h(item.name)}</b> for {item.price} 🪙")


# =========================================
# STATISTICS
# =========================================
@impl("stats", "userstats", "topusers", "topchatters", "messages", "activity")
async def cmd_stats(update, ctx, name):
    chat = update.effective_chat
    gid, now = chat.id, time.time()
    flush_counters()
    if name == "stats":
        with db() as s:
            total = s.execute(select(func.coalesce(func.sum(XP.messages), 0)).where(XP.group_id == gid)).scalar()
            m24 = s.execute(select(func.count()).select_from(MsgLog).where(MsgLog.group_id == gid, MsgLog.ts > now - 86400)).scalar()
            users = s.execute(select(func.count()).select_from(XP).where(XP.group_id == gid)).scalar()
        try:
            members = await ctx.bot.get_chat_member_count(gid)
        except TelegramError:
            members = "?"
        return await reply(update, f"📊 <b>{h(chat.title)}</b>\n👥 Members: {members}\n💬 Messages tracked: {total} (24h: {m24})\n"
                                   f"🗣️ Active users: {users}\n⚠️ Active warnings: {db_count(Warning, Warning.group_id == gid)}\n"
                                   f"🔨 Mod actions: {db_count(AdminLog, AdminLog.group_id == gid)}")
    if name in ("userstats", "messages"):
        tid, _ = await _target_or_self(update, ctx)
        with db() as s:
            row = _xp_row(s, gid, tid)
            m24 = s.execute(select(func.count()).select_from(MsgLog).where(MsgLog.group_id == gid, MsgLog.user_id == tid, MsgLog.ts > now - 86400)).scalar()
        if name == "messages":
            return await reply(update, f"💬 {mention(tid)}: <b>{row.messages}</b> messages (24h: {m24})")
        return await reply(update, f"👤 {mention(tid)}\n💬 Messages: {row.messages} (24h {m24})\n⭐ Level {row.level} · {row.xp} XP\n"
                                   f"⚠️ Warnings: {db_count(Warning, Warning.group_id == gid, Warning.user_id == tid)}\n"
                                   f"🚪 Joins: {db_count(JoinLog, JoinLog.group_id == gid, JoinLog.user_id == tid, JoinLog.event == 'join')}")
    with db() as s:
        if name == "topusers":
            rows = s.execute(select(XP.user_id, XP.messages).where(XP.group_id == gid).order_by(XP.messages.desc()).limit(10)).all()
            title = "🗣️ <b>TOP USERS (all time)</b>"
        elif name == "topchatters":
            rows = s.execute(select(MsgLog.user_id, func.count().label("c")).where(MsgLog.group_id == gid, MsgLog.ts > now - 86400)
                             .group_by(MsgLog.user_id).order_by(func.count().desc()).limit(10)).all()
            title = "💬 <b>TOP CHATTERS (24h)</b>"
        else:
            tzinfo = tz_of(gid)
            stamps = s.execute(select(MsgLog.ts).where(MsgLog.group_id == gid, MsgLog.ts > now - 86400)).scalars().all()
            buckets = [0] * 24
            for t in stamps:
                buckets[datetime.fromtimestamp(t, tzinfo).hour] += 1
            peak = max(buckets) or 1
            lines = [f"{hr:02d}h {'█' * round(c * 12 / peak)} {c}" for hr, c in enumerate(buckets) if c]
            return await reply(update, "📈 <b>ACTIVITY (24h)</b>\n<pre>" + ("\n".join(lines) or "No data yet") + "</pre>")
    await reply(update, title + "\n" + ("\n".join(f"{i}. {mention(u)} — {c}" for i, (u, c) in enumerate(rows, 1)) or "No data yet."))


# =========================================
# USER INFORMATION
# =========================================
@impl("info", "id", "whois", "avatar", "profile", "history", "joins", "username")
async def cmd_user(update, ctx, name):
    chat, me = update.effective_chat, update.effective_user
    grp = is_group(chat)
    tid, args = await resolve_target(update, ctx)
    if not tid and name in ("username", "id") and ctx.args and ctx.args[0].startswith("@"):
        return await reply(update, "❓ I don't know that username yet.")
    tid = tid or me.id
    if name == "id":
        out = f"🆔 User: <code>{tid}</code>"
        if grp:
            out += f"\n💬 Chat: <code>{chat.id}</code>"
        return await reply(update, out)
    with db() as s:
        u = s.get(User, tid)
    if name == "username":
        return await reply(update, f"👤 <code>{tid}</code> → " + (f"@{u.username}" if u and u.username else "no known username"))
    if name == "avatar":
        try:
            photos = await ctx.bot.get_user_profile_photos(tid, limit=1)
            if not photos.photos:
                return await reply(update, "🖼️ No visible profile photo.")
            return await update.effective_message.reply_photo(photos.photos[0][-1].file_id, caption=h(display(tid)))
        except TelegramError as e:
            return await reply(update, f"❌ {h(e.message)}")
    if name in ("history", "joins", "whois") and grp and await get_role(ctx.bot, chat.id, me.id) < 1:
        return await reply(update, "🚫 Moderators only.")
    gid = chat.id if grp else 0
    if name == "history":
        with db() as s:
            rows = s.execute(select(AdminLog).where(AdminLog.group_id == gid, AdminLog.target_id == tid).order_by(AdminLog.ts.desc()).limit(15)).scalars().all()
        return await reply(update, f"📜 <b>HISTORY</b> — {mention(tid)}\n" + ("\n".join(f"{fmt_ts(r.ts, gid)} · <b>{r.action}</b> · {h(r.reason or '—')}" for r in rows) or "Clean record."))
    if name == "joins":
        with db() as s:
            rows = s.execute(select(JoinLog).where(JoinLog.group_id == gid, JoinLog.user_id == tid).order_by(JoinLog.ts.desc()).limit(15)).scalars().all()
        return await reply(update, f"🚪 <b>JOINS</b> — {mention(tid)}\n" + ("\n".join(f"{fmt_ts(r.ts, gid)} · {r.event}" for r in rows) or "No recorded joins."))
    role = ROLE_NAMES[await get_role(ctx.bot, chat.id, tid)] if grp else "—"
    lines = [f"👤 <b>{h(display(tid))}</b>", f"🆔 <code>{tid}</code>"]
    if u and u.username:
        lines.append(f"🔗 @{u.username}")
    if grp:
        lines.append(f"🎖️ Role: {role}")
        lines.append(f"⚠️ Warnings: {db_count(Warning, Warning.group_id == gid, Warning.user_id == tid)}/{gget(gid, 'warn_limit')}")
        if name in ("whois", "profile"):
            with db() as s:
                row = _xp_row(s, gid, tid)
                bal = _eco_row(s, gid, tid).coins
                items = s.execute(select(Inventory.item).where(Inventory.group_id == gid, Inventory.user_id == tid)).scalars().all()
            lines.append(f"⭐ Level {row.level} · {row.xp} XP · 💬 {row.messages}")
            lines.append(f"💰 {bal} 🪙" + (f" · 🎒 {h(', '.join(items))}" if items else ""))
        if name == "whois":
            lines.append(f"🔨 Mod actions on user: {db_count(AdminLog, AdminLog.group_id == gid, AdminLog.target_id == tid)}")
        with db() as s:
            j = s.execute(select(JoinLog.ts).where(JoinLog.group_id == gid, JoinLog.user_id == tid, JoinLog.event == "join").order_by(JoinLog.ts.desc())).scalars().first()
        if j:
            lines.append(f"🚪 Last joined: {fmt_ts(j, gid)}")
    if u:
        lines.append(f"👁️ First seen by bot: {fmt_ts(u.first_seen)}")
    await reply(update, "\n".join(lines))


# =========================================
# ADMINISTRATION (Telegram promotion + bot-level roles)
# =========================================
def _roles_of(gid: int, role: str) -> list[int]:
    with db() as s:
        return list(s.execute(select(GroupAdmin.user_id).where(GroupAdmin.group_id == gid, GroupAdmin.role == role)).scalars())


@impl("admins", "owner", "admin", "trusted", "staff")
async def cmd_roles(update, ctx, name):
    chat, me = update.effective_chat, update.effective_user
    if name == "staff":
        args = ctx.args or []
        if args and args[0].lower() in ("add", "remove"):
            if me.id != OWNER_ID:
                return await reply(update, "🚫 Only the bot owner can manage staff.")
            ctx.args = args[1:]
            tid, _ = await resolve_target(update, ctx)
            if not tid:
                return await reply(update, NO_TARGET)
            with db() as s:
                s.execute(delete(GroupAdmin).where(GroupAdmin.group_id == 0, GroupAdmin.user_id == tid, GroupAdmin.role == "staff"))
                if args[0].lower() == "add":
                    s.add(GroupAdmin(group_id=0, user_id=tid, role="staff", added_by=me.id, ts=time.time()))
            return await reply(update, f"✅ {mention(tid)} {'added to' if args[0].lower() == 'add' else 'removed from'} bot staff.")
        ids = _roles_of(0, "staff")
        return await reply(update, "🛠️ <b>BOT STAFF</b>\n" + ("\n".join(mention(u) for u in ids) if ids else "No staff members."))
    gid = chat.id
    if name == "trusted":
        ids = _roles_of(gid, "trusted")
        return await reply(update, "🤝 <b>TRUSTED ADMINS</b>\n" + ("\n".join(mention(u) for u in ids) if ids else "None."))
    if name in ("admins", "owner"):
        admins = await ctx.bot.get_chat_administrators(gid)
        for a in admins:
            upsert_user(a.user)
        if name == "owner":
            o = next((a for a in admins if a.status == CMS.OWNER), None)
            return await reply(update, f"👑 Group owner: {mention(o.user.id, o.user.full_name)}" if o else "👑 Owner not visible.")
        lines = [f"{'👑' if a.status == CMS.OWNER else '👮'} {mention(a.user.id, a.user.full_name)}" + (f" — {h(a.custom_title)}" if getattr(a, 'custom_title', None) else "")
                 for a in admins if not a.user.is_bot]
        return await reply(update, f"👮 <b>ADMINS</b> ({len(lines)})\n" + "\n".join(lines))
    tid, _ = await _target_or_self(update, ctx)
    role = await get_role(ctx.bot, gid, tid)
    await reply(update, f"👤 {mention(tid)} — <b>{ROLE_NAMES[role]}</b>")


@impl("promote", "demote")
async def cmd_promote(update, ctx, name):
    chat, me = update.effective_chat, update.effective_user
    tid, args = await resolve_target(update, ctx)
    if not tid:
        return await reply(update, NO_TARGET)
    err = await safety(ctx, chat.id, me.id, tid, right="can_promote_members", rank_check=(name == "demote"))
    if err:
        return await reply(update, err)
    if name == "promote":
        await ctx.bot.promote_chat_member(chat.id, tid, can_delete_messages=True, can_restrict_members=True,
                                          can_pin_messages=True, can_invite_users=True, can_manage_video_chats=True)
        if args:
            try:
                await ctx.bot.set_chat_administrator_custom_title(chat.id, tid, " ".join(args)[:16])
            except TelegramError:
                pass
    else:
        await ctx.bot.promote_chat_member(chat.id, tid, can_delete_messages=False, can_restrict_members=False,
                                          can_pin_messages=False, can_invite_users=False, can_manage_video_chats=False,
                                          can_change_info=False, can_promote_members=False, can_manage_chat=False)
    _RC.pop((chat.id, tid), None)
    await alog(ctx.bot, chat.id, name.upper(), me.id, tid, "Telegram admin rights")
    await reply(update, f"✅ {mention(tid)} {'promoted' if name == 'promote' else 'demoted'}.")


@impl("setadmin", "deladmin", "trust", "untrust")
async def cmd_localrole(update, ctx, name):
    chat, me = update.effective_chat, update.effective_user
    tid, args = await resolve_target(update, ctx)
    if not tid:
        return await reply(update, NO_TARGET)
    if tid == ctx.bot.id or tid == me.id:
        return await reply(update, "🙅 Pick someone else.")
    role = "trusted" if name in ("trust", "untrust") else ("moderator" if args and args[0].lower().startswith("mod") else "admin")
    with db() as s:
        if name in ("deladmin", "untrust"):
            s.execute(delete(GroupAdmin).where(GroupAdmin.group_id == chat.id, GroupAdmin.user_id == tid,
                                               GroupAdmin.role.in_(["moderator", "admin"] if name == "deladmin" else ["trusted"])))
        else:
            if not s.execute(select(GroupAdmin.id).where(GroupAdmin.group_id == chat.id, GroupAdmin.user_id == tid, GroupAdmin.role == role)).scalar():
                s.add(GroupAdmin(group_id=chat.id, user_id=tid, role=role, added_by=me.id, ts=time.time()))
    await alog(ctx.bot, chat.id, "PROMOTE" if name in ("setadmin", "trust") else "DEMOTE", me.id, tid, f"bot role: {role}")
    await reply(update, f"✅ {mention(tid)}: bot role <b>{role}</b> {'granted' if name in ('setadmin', 'trust') else 'removed'}.\n"
                        "<i>Bot-level roles don't change Telegram admin rights (use /promote for that).</i>")


@impl("pin", "unpin", "pinned", "silent", "notify")
async def cmd_pin(update, ctx, name):
    chat, msg = update.effective_chat, update.effective_message
    if name == "pinned":
        c = await ctx.bot.get_chat(chat.id)
        if not c.pinned_message:
            return await reply(update, "📌 Nothing pinned.")
        pm = c.pinned_message
        link = f"https://t.me/{chat.username}/{pm.message_id}" if chat.username else f"https://t.me/c/{str(chat.id)[4:]}/{pm.message_id}"
        return await reply(update, f'📌 <a href="{link}">Jump to the pinned message</a>')
    if not await bot_can(ctx, chat.id, "can_pin_messages"):
        return await reply(update, "❌ I need the “Pin messages” admin permission first.")
    if name == "unpin":
        if ctx.args and ctx.args[0].lower() == "all":
            await ctx.bot.unpin_all_chat_messages(chat.id)
            return await reply(update, "📌 All messages unpinned.")
        r = msg.reply_to_message
        await ctx.bot.unpin_chat_message(chat.id, message_id=r.message_id if r else None)
        return await reply(update, "📌 Unpinned.")
    r = msg.reply_to_message
    if not r:
        return await reply(update, "↩️ Reply to the message you want to pin.")
    loud = {"pin": gget(chat.id, "pin_notify") or bool(ctx.args and ctx.args[0].lower() in ("loud", "notify")),
            "silent": False, "notify": True}[name]
    await ctx.bot.pin_chat_message(chat.id, r.message_id, disable_notification=not loud)
    await reply(update, f"📌 Pinned{' (silently)' if not loud else ''}.")


def parse_when(tokens: list[str], tz):
    """Returns (timestamp, tokens_used) or (None, 0). Accepts 30m/2h/1d, HH:MM, YYYY-MM-DD HH:MM (group timezone)."""
    if not tokens:
        return None, 0
    d = parse_duration(tokens[0])
    if d:
        return time.time() + d, 1
    now = datetime.now(tz)
    if re.fullmatch(r"\d{1,2}:\d{2}", tokens[0]):
        hh, mm = map(int, tokens[0].split(":"))
        if hh < 24 and mm < 60:
            t = now.replace(hour=hh, minute=mm, second=0, microsecond=0)
            return (t + timedelta(days=1) if t <= now else t).timestamp(), 1
    if len(tokens) > 1 and re.fullmatch(r"\d{4}-\d{2}-\d{2}", tokens[0]) and re.fullmatch(r"\d{1,2}:\d{2}", tokens[1]):
        try:
            return datetime.strptime(f"{tokens[0]} {tokens[1]}", "%Y-%m-%d %H:%M").replace(tzinfo=tz).timestamp(), 2
        except ValueError:
            pass
    return None, 0


@impl("schedule")
async def cmd_schedule(update, ctx, name):
    chat, me, msg = update.effective_chat, update.effective_user, update.effective_message
    args = list(ctx.args or [])
    if args and args[0].lower() == "list":
        with db() as s:
            rows = s.execute(select(ScheduledTask).where(ScheduledTask.group_id == chat.id, ScheduledTask.kind == "announce", ScheduledTask.done == False).order_by(ScheduledTask.run_at)).scalars().all()  # noqa: E712
        return await reply(update, "🗓️ <b>SCHEDULED</b>\n" + ("\n".join(f"#{r.id} · {fmt_ts(r.run_at, chat.id)} · {h((json.loads(r.payload).get('text') or '[message]')[:40])}" for r in rows) or "Nothing scheduled."))
    if len(args) == 2 and args[0].lower() == "cancel" and args[1].isdigit():
        with db() as s:
            t = s.get(ScheduledTask, int(args[1]))
            ok = bool(t and t.group_id == chat.id and t.kind == "announce")
        if ok:
            cancel_task(int(args[1]))
        return await reply(update, "🗑️ Cancelled." if ok else "❓ No such scheduled announcement.")
    ts, used = parse_when(args, tz_of(chat.id))
    if not ts or ts < time.time() + 30:
        return await reply(update, "Usage: <code>/schedule &lt;30m | 2h | 18:30 | 2026-12-31 09:00&gt; &lt;text&gt;</code> (or reply to a message)\n"
                                   "Also: <code>/schedule list</code>, <code>/schedule cancel &lt;id&gt;</code>. Times use the group timezone.")
    text, r = " ".join(args[used:]), msg.reply_to_message
    if r:
        payload = {"from_chat": chat.id, "message_id": r.message_id}
    elif text:
        payload = {"text": text}
    else:
        return await reply(update, "Give the announcement text or reply to a message.")
    tid = schedule_task("announce", chat.id, me.id, ts, payload)
    await reply(update, f"🗓️ Announcement <b>#{tid}</b> scheduled for {fmt_ts(ts, chat.id)} ({gget(chat.id, 'timezone')}).")


# =========================================
# SETTINGS
# =========================================
SECTIONS = {
    "moderation": ("🛡️ Moderation", [("adminprotect", "b"), ("adminmoderation", "b"), ("auto_delete", "b"), ("auto_warn", "b"), ("auto_mute", "b"), ("auto_ban", "b")]),
    "warnings": ("⚠️ Warnings", [("warn_limit", "i", 1, 2, 20), ("warn_action", "c", ["mute", "kick", "ban"])]),
    "locks": ("🔒 Locks", []),
    "security": ("🔐 Security", [(k, "b") for k in SEC_KEYS] + [("flood_limit", "i", 1, 2, 30), ("mention_limit", "i", 1, 2, 30), ("raid_threshold", "i", 1, 3, 100), ("captcha_timeout", "i", 1, 1, 60)]),
    "welcome": ("👋 Welcome", [("welcome", "b"), ("clean_service", "b")]),
    "goodbye": ("👋 Goodbye", [("goodbye", "b")]),
    "filters": ("📝 Filters", [("filters_on", "b")]),
    "logs": ("📋 Logs", []),
    "xp": ("⭐ XP", [("xp", "b"), ("xp_announce", "b"), ("xp_cooldown", "i", 10, 10, 600)]),
    "economy": ("💰 Economy", [("economy", "b"), ("daily_amount", "i", 50, 0, 10000), ("weekly_amount", "i", 100, 0, 50000), ("monthly_amount", "i", 500, 0, 200000)]),
    "language": ("🌐 Language", [("language", "c", ["en", "hi"])]),
    "timezone": ("🕒 Timezone", []),
}
SECTION_ORDER = list(SECTIONS)


def panel_home(gid: int):
    rows = [[Btn(SECTIONS[k][0], callback_data=f"sp:{gid}:{k}") for k in SECTION_ORDER[i:i + 2]] for i in range(0, len(SECTION_ORDER), 2)]
    return "⚙️ <b>SETTINGS</b>\nEvery group has its own independent settings. Choose a section:", Kb(rows)


def panel(gid: int, section: str):
    if section == "home":
        return panel_home(gid)
    if section == "locks":
        return locks_view(gid, back=True)
    title, items = SECTIONS[section]
    lines, rows, bools = [f"<b>{title}</b>", ""], [], []
    for it in items:
        key, kind, val = it[0], it[1], gget(gid, it[0])
        if kind == "b":
            bools.append(Btn(f"{'🟢' if val else '🔴'} {key}", callback_data=f"sx:{gid}:{key}:t:{section}"))
        elif kind == "i":
            rows.append([Btn("➖", callback_data=f"sx:{gid}:{key}:-:{section}"), Btn(f"{key}: {val}", callback_data=f"sx:{gid}:{key}:n:{section}"),
                         Btn("➕", callback_data=f"sx:{gid}:{key}:+:{section}")])
        else:
            rows.append([Btn(f"{key}: {val}", callback_data=f"sx:{gid}:{key}:t:{section}")])
    rows = [bools[i:i + 2] for i in range(0, len(bools), 2)] + rows
    if section == "logs":
        with db() as s:
            logs = s.execute(select(AdminLog).where(AdminLog.group_id == gid).order_by(AdminLog.ts.desc()).limit(8)).scalars().all()
        lines += [f"{fmt_ts(r.ts, gid)} · <b>{r.action}</b> · {h(display(r.target_id)) if r.target_id else '—'}" for r in logs] or ["No actions logged yet."]
        lines.append(f"\nLog channel: <code>{gget(gid, 'log_chat') or 'not set'}</code> (<code>/settings set log_chat -100…</code>)")
    elif section == "timezone":
        lines.append(f"Timezone: <b>{gget(gid, 'timezone')}</b> — now {datetime.now(tz_of(gid)).strftime('%H:%M')}\nChange: <code>/timezone Asia/Kolkata</code>")
    elif section == "filters":
        lines.append(f"Filters: {len([f for f in get_filters(gid) if f['action'] == 'reply'])} · Blocked: {len([f for f in get_filters(gid) if f['action'] != 'reply'])}")
    elif section == "warnings":
        lines.append("Warnings expire only when removed. Use ➖/➕ to change the limit.")
    rows.append([Btn("⬅️ Back", callback_data=f"sp:{gid}:home")])
    return "\n".join(lines), Kb(rows)


def _coerce(key: str, raw: str):
    d = DEFAULTS[key]
    if isinstance(d, bool):
        if raw.lower() not in ("on", "off", "true", "false", "yes", "no", "1", "0"):
            raise ValueError("use on/off")
        return raw.lower() in ("on", "true", "yes", "1")
    if isinstance(d, int):
        return int(raw)
    if key == "timezone":
        ZoneInfo(raw)
    if key == "language" and raw not in ("en", "hi"):
        raise ValueError("en or hi")
    if key == "warn_action" and raw not in ("mute", "kick", "ban"):
        raise ValueError("mute/kick/ban")
    return raw


@impl("settings", "setprefix", "language", "timezone")
async def cmd_settings(update, ctx, name):
    chat, me = update.effective_chat, update.effective_user
    gid, args = chat.id, list(ctx.args or [])
    if name == "setprefix":
        if not args:
            return await reply(update, f"Prefix: <code>{h(gget(gid, 'prefix') or 'none')}</code>. Usage: <code>/setprefix !</code> or <code>/setprefix off</code>")
        val = "" if args[0].lower() == "off" else args[0][:2]
        if val == "/":
            return await reply(update, "“/” always works already.")
        gset(gid, "prefix", val)
        return await reply(update, f"✅ Prefix {'disabled' if not val else f'set to <code>{h(val)}</code> (e.g. {h(val)}ban @user)'}.")
    if name in ("language", "timezone"):
        key = name
        if not args:
            return await reply(update, f"{name.title()}: <b>{gget(gid, key)}</b>\nUsage: <code>{h(META[name]['usage'])}</code>")
        try:
            gset(gid, key, _coerce(key, args[0]))
        except Exception as e:
            return await reply(update, f"❌ Invalid value ({h(e)}).")
        return await reply(update, f"✅ {name.title()} set to <b>{h(args[0])}</b>.")
    if args and args[0].lower() == "set":
        if len(args) < 3 or args[1] not in DEFAULTS:
            return await reply(update, "Keys: <code>" + " ".join(sorted(DEFAULTS)) + "</code>")
        try:
            gset(gid, args[1], _coerce(args[1], args[2]))
        except Exception as e:
            return await reply(update, f"❌ Invalid value ({h(e)}).")
        await alog(ctx.bot, gid, "SECURITY", me.id, 0, f"{args[1]}={args[2]}")
        return await reply(update, f"✅ <code>{args[1]}</code> = <b>{h(args[2])}</b>")
    text, kb = panel_home(gid)
    await reply(update, text, reply_markup=kb)


@impl("security")
async def cmd_security(update, ctx, name):
    gid = update.effective_chat.id
    lines = ["🛡️ <b>SECURITY</b>\n"] + [f"{k.replace('anti', 'Anti-').title() if k.startswith('anti') else k.title()}: {'🟢' if gget(gid, k) else '🔴'}" for k in SEC_KEYS]
    text, kb = panel(gid, "security")
    await reply(update, "\n".join(lines[:1] + lines[1:]) + "\n\nTap to toggle:", reply_markup=kb)


# =========================================
# FUN
# =========================================
BALL = ["It is certain.", "Without a doubt.", "Yes — definitely.", "Most likely.", "Signs point to yes.", "Reply hazy, try again.",
        "Ask again later.", "Cannot predict now.", "Don't count on it.", "My sources say no.", "Very doubtful.", "Outlook not so good."]
JOKES = ["Why do programmers prefer dark mode? Because light attracts bugs.", "I told my computer I needed a break. It said: no problem, I'll go to sleep.",
         "Why did the developer go broke? Because he used up all his cache.", "There are 10 kinds of people: those who understand binary and those who don't.",
         "A SQL query walks into a bar, walks up to two tables and asks: “Can I join you?”"]
QUOTES = ["“The only way to do great work is to love what you do.” — Steve Jobs", "“Well done is better than well said.” — Benjamin Franklin",
          "“It always seems impossible until it's done.” — Nelson Mandela", "“Whether you think you can or you think you can't, you're right.” — Henry Ford",
          "“Simplicity is the ultimate sophistication.” — Leonardo da Vinci"]
TRUTHS = ["What's the most embarrassing thing you've done online?", "What's a habit you're trying to break?", "What's the last lie you told?",
          "Which app do you waste the most time on?", "What's a skill you pretend to have?"]
DARES = ["Send a voice message singing the alphabet.", "Change your profile photo to a potato for an hour.", "Type your next message using only emojis.",
         "Say something nice about every admin here.", "Send the 5th photo in your gallery (SFW!)."]


@impl("8ball", "dice", "coin", "roll", "choose", "ship", "hug", "slap", "highfive", "joke", "quote", "truth", "dare")
async def cmd_fun(update, ctx, name):
    me, args, msg = update.effective_user, list(ctx.args or []), update.effective_message
    if name == "8ball":
        return await reply(update, f"🎱 {random.choice(BALL)}" if args else "🎱 Ask a question: <code>/8ball will it work?</code>")
    if name == "dice":
        return await msg.reply_dice(emoji=args[0] if args and args[0] in "🎲🎯🏀⚽🎳🎰" else "🎲")
    if name == "coin":
        return await reply(update, f"🪙 {random.choice(['Heads', 'Tails'])}!")
    if name == "roll":
        m = re.fullmatch(r"(\d{1,2})?d(\d{1,4})", args[0].lower()) if args else None
        n, sides = (int(m[1] or 1), int(m[2])) if m else (1, int(args[0]) if args and args[0].isdigit() else 6)
        if n < 1 or sides < 2:
            return await reply(update, "Usage: <code>/roll 2d6</code>")
        rolls = [random.randint(1, sides) for _ in range(n)]
        return await reply(update, f"🎲 {rolls} = <b>{sum(rolls)}</b>")
    if name == "choose":
        opts = [o.strip() for o in re.split(r"[,|]| or ", " ".join(args)) if o.strip()]
        return await reply(update, f"🤔 I choose: <b>{h(random.choice(opts))}</b>" if len(opts) > 1 else "Usage: <code>/choose pizza, burger, pasta</code>")
    if name == "ship":
        names = [a.lstrip("@") for a in args][:2]
        if len(names) < 2 and msg.reply_to_message and msg.reply_to_message.from_user:
            names = [me.first_name, msg.reply_to_message.from_user.first_name]
        if len(names) < 2:
            return await reply(update, "Usage: <code>/ship name1 name2</code> or reply to someone.")
        pct = int(hashlib.sha256("|".join(sorted(n.lower() for n in names)).encode()).hexdigest(), 16) % 101
        return await reply(update, f"💘 <b>{h(names[0])}</b> + <b>{h(names[1])}</b>\n{'❤️' * (pct // 20)}{'🖤' * (5 - pct // 20)} <b>{pct}%</b>")
    if name in ("hug", "slap", "highfive"):
        tid, _ = await resolve_target(update, ctx)
        other = mention(tid) if tid else (h(" ".join(args)) if args else "themselves")
        verb = {"hug": "🤗 hugs", "slap": "👋 slaps", "highfive": "🙌 high-fives"}[name]
        return await reply(update, f"{mention(me.id, me.full_name)} {verb} {other}")
    await reply(update, {"joke": lambda: "😄 " + random.choice(JOKES), "quote": lambda: "💬 " + random.choice(QUOTES),
                          "truth": lambda: "🧐 <b>Truth:</b> " + random.choice(TRUTHS), "dare": lambda: "😈 <b>Dare:</b> " + random.choice(DARES)}[name]())


# =========================================
# OWNER SYSTEM
# =========================================
_CONF: dict = {}
_DRAFTS: dict = {}


def confirm_kb(uid: int, fn, *args) -> Kb:
    token = secrets.token_hex(4)
    _CONF[token] = (uid, fn, args, time.time() + 120)
    return Kb([[Btn("🔴 CONFIRM", callback_data=f"cf:{token}:y"), Btn("❌ CANCEL", callback_data=f"cf:{token}:n")]])


async def act_bot_switch(ctx, on: bool) -> str:
    bset("bot_enabled", on)
    return "🟢 Ivy is now <b>enabled</b> globally." if on else "🔴 Ivy is now <b>disabled</b> globally (process keeps running)."


async def act_maint(ctx, on: bool) -> str:
    bset("maintenance_mode", on)
    return f"🔧 Maintenance mode <b>{'ON' if on else 'OFF'}</b>."


async def act_groups_all(ctx, on: bool) -> str:
    with db() as s:
        for g in s.execute(select(Group)).scalars():
            g.enabled = on
    _GEN.clear()
    return f"{'🟢' if on else '🔴'} All groups {'enabled' if on else 'disabled'}."


async def act_group(ctx, gid: int, on: bool) -> str:
    with db() as s:
        g = s.get(Group, gid)
        if not g:
            return "❓ Unknown group."
        g.enabled = on
    _GEN[gid] = on
    return f"{'🟢' if on else '🔴'} Group <code>{gid}</code> {'enabled' if on else 'disabled'}."


async def act_restart(ctx) -> str:
    async def _r():
        await asyncio.sleep(1.5)
        flush_counters()
        os.execv(sys.executable, [sys.executable] + sys.argv)
    bg(_r())
    return "♻️ Restarting…"


def owner_panel():
    with db() as s:
        users = s.execute(select(func.count()).select_from(User)).scalar()
        groups = s.execute(select(func.count()).select_from(Group).where(Group.left == False)).scalar()  # noqa: E712
    bans, mutes = db_count(AdminLog, AdminLog.action == "BAN"), db_count(AdminLog, AdminLog.action == "MUTE")
    state = "🟢 ONLINE" if bot_online() else ("🔧 MAINTENANCE" if bget("bot_enabled", True) else "🔴 DISABLED")
    text = (f"🤖 <b>{h(BOT_NAME.upper())} OWNER PANEL</b>\n\n{state.split()[0]} Bot Status: <b>{state.split()[1]}</b>\n\n"
            f"👥 Users: {users}\n🏠 Groups: {groups}\n\n⚠️ Warnings: {db_count(Warning)}\n🚫 Bans: {bans}\n🔇 Mutes: {mutes}\n\n⚡ Uptime: {uptime_str()}")
    kb = Kb([[Btn("🏠 Groups", callback_data="ogl:0"), Btn("👥 Users", callback_data="own:users")],
             [Btn("📢 Broadcast", callback_data="own:bc"), Btn("⚙️ Settings", callback_data="own:set")],
             [Btn("📊 Statistics", callback_data="own:stats"), Btn("🔧 Maintenance", callback_data="own:maint")]])
    return text, kb


@impl("bot")
async def cmd_bot(update, ctx, name):
    text, kb = owner_panel()
    await reply(update, text, reply_markup=kb)


@impl("botstatus", "health", "database")
async def cmd_ownerinfo(update, ctx, name):
    if name == "database":
        lines = []
        with db() as s:
            for t in Base.metadata.sorted_tables:
                lines.append(f"{t.name}: {s.execute(select(func.count()).select_from(t)).scalar()}")
        size = Path(DATABASE_URL.replace("sqlite:///", "")).stat().st_size / 1024 if _IS_SQLITE and Path(DATABASE_URL.replace("sqlite:///", "")).exists() else 0
        return await reply(update, f"🗄️ <b>DATABASE</b> ({size:.0f} KB)\n<pre>" + "\n".join(lines) + "</pre>")
    t0 = time.perf_counter()
    await ctx.bot.get_me()
    api_ms = (time.perf_counter() - t0) * 1000
    try:
        with db() as s:
            s.execute(select(1))
        dbok = "🟢"
    except Exception:
        dbok = "🔴"
    try:
        import resource
        mem = f"{resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024:.0f} MB"
    except Exception:
        mem = "n/a"
    import telegram
    await reply(update, f"🩺 <b>{'HEALTH' if name == 'health' else 'BOT STATUS'}</b>\nState: {'🟢 online' if bot_online() else '🔴 off/maintenance'}\n"
                        f"Telegram API: {api_ms:.0f} ms\nDatabase: {dbok}\nScheduler jobs: {len(SCHED.get_jobs())}\nUptime: {uptime_str()}\n"
                        f"Memory: {mem}\nPython {sys.version.split()[0]} · PTB {telegram.__version__}\nErrors logged: {len(ERRORS)}")


@impl("boton", "botoff", "maintenance", "maintenance_on", "maintenance_off")
async def cmd_botswitch(update, ctx, name):
    uid, args = update.effective_user.id, list(ctx.args or [])
    if name == "boton":
        return await reply(update, await act_bot_switch(ctx, True))
    if name == "botoff":
        return await reply(update, "⚠️ <b>CONFIRM</b>\n\nYou are about to disable Ivy globally.", reply_markup=confirm_kb(uid, act_bot_switch, False))
    if name == "maintenance" and not args:
        return await reply(update, f"🔧 Maintenance: <b>{'ON' if bget('maintenance_mode', False) else 'OFF'}</b>\nUse <code>/maintenance on/off</code>")
    on = name == "maintenance_on" or (args and args[0].lower() == "on")
    if on:
        return await reply(update, "⚠️ <b>CONFIRM</b>\n\nEnable maintenance mode? Non-owners will be blocked.", reply_markup=confirm_kb(uid, act_maint, True))
    await reply(update, await act_maint(ctx, False))


@impl("restart")
async def cmd_restart(update, ctx, name):
    await reply(update, "⚠️ <b>CONFIRM</b>\n\nRestart the Ivy process now?", reply_markup=confirm_kb(update.effective_user.id, act_restart))


def _gid_arg(update, ctx):
    if ctx.args and re.fullmatch(r"-?\d+", ctx.args[0]):
        return int(ctx.args[0])
    return update.effective_chat.id if is_group(update.effective_chat) else None


@impl("offall", "onall", "offgroup", "ongroup")
async def cmd_groupswitch(update, ctx, name):
    uid, on = update.effective_user.id, name in ("onall", "ongroup")
    if name in ("offall", "onall"):
        return await reply(update, f"⚠️ <b>CONFIRM</b>\n\n{'Enable' if on else 'Disable'} Ivy in <b>every</b> group?", reply_markup=confirm_kb(uid, act_groups_all, on))
    gid = _gid_arg(update, ctx)
    if not gid:
        return await reply(update, f"Usage: <code>{h(META[name]['usage'])}</code>")
    if on:
        return await reply(update, await act_group(ctx, gid, True))
    await reply(update, f"⚠️ <b>CONFIRM</b>\n\nDisable Ivy in <code>{gid}</code>?", reply_markup=confirm_kb(uid, act_group, gid, False))


def groups_page(page: int):
    with db() as s:
        rows = s.execute(select(Group).where(Group.left == False).order_by(Group.title)).scalars().all()  # noqa: E712
    pages = max(1, -(-len(rows) // 8))
    page = max(0, min(page, pages - 1))
    btns = [[Btn(f"{'🟢' if g.enabled else '🔴'} {(g.title or g.group_id)}"[:40], callback_data=f"grp:{g.group_id}:home")] for g in rows[page * 8:(page + 1) * 8]]
    btns.append([Btn("⬅️", callback_data=f"ogl:{max(0, page - 1)}"), Btn(f"{page + 1}/{pages}", callback_data="own:home"), Btn("➡️", callback_data=f"ogl:{min(pages - 1, page + 1)}")])
    btns.append([Btn("🏠 Home", callback_data="own:home")])
    return f"🏠 <b>GROUPS</b> ({len(rows)})\nSelect a group to manage:", Kb(btns)


@impl("groups")
async def cmd_groups(update, ctx, name):
    text, kb = groups_page(0)
    await reply(update, text, reply_markup=kb)


async def group_view(ctx, gid: int, section: str):
    with db() as s:
        g = s.get(Group, gid)
    if not g:
        return "❓ Unknown group.", Kb([[Btn("⬅️ Groups", callback_data="ogl:0")]])
    back = Btn("⬅️ Back", callback_data=f"grp:{gid}:home")
    if section == "home":
        text = f"🏠 <b>GROUP CONTROL</b>\n<b>{h(g.title)}</b>\n<code>{gid}</code> · {'🟢 enabled' if g.enabled else '🔴 disabled'}"
        kb = Kb([[Btn("👥 Members", callback_data=f"grp:{gid}:members"), Btn("👮 Admins", callback_data=f"grp:{gid}:admins")],
                 [Btn("🛡️ Moderation", callback_data=f"grp:{gid}:mod"), Btn("🔒 Locks", callback_data=f"sp:{gid}:locks")],
                 [Btn("🔐 Security", callback_data=f"sp:{gid}:security"), Btn("👋 Welcome", callback_data=f"sp:{gid}:welcome")],
                 [Btn("📝 Filters", callback_data=f"sp:{gid}:filters"), Btn("📊 Statistics", callback_data=f"grp:{gid}:stats")],
                 [Btn("⚙️ Settings", callback_data=f"sp:{gid}:home"), Btn("📋 Logs", callback_data=f"lg:{gid}:0")],
                 [Btn("🔴 Disable" if g.enabled else "🟢 Enable", callback_data=f"grp:{gid}:tog"), Btn("⬅️ Groups", callback_data="ogl:0")]])
        return text, kb
    try:
        if section == "members":
            n = await ctx.bot.get_chat_member_count(gid)
            j = db_count(JoinLog, JoinLog.group_id == gid, JoinLog.event == "join", JoinLog.ts > time.time() - 86400)
            text = f"👥 <b>MEMBERS</b>\nTotal: {n}\nJoined (24h): {j}"
        elif section == "admins":
            adm = await ctx.bot.get_chat_administrators(gid)
            text = "👮 <b>ADMINS</b>\n" + "\n".join(f"{'👑' if a.status == CMS.OWNER else '👮'} {h(a.user.full_name)}" for a in adm if not a.user.is_bot)
        elif section == "mod":
            text = (f"🛡️ <b>MODERATION</b>\nWarn limit: {gget(gid, 'warn_limit')} → {gget(gid, 'warn_action')}\nActive warnings: {db_count(Warning, Warning.group_id == gid)}\n"
                    f"Bans: {db_count(AdminLog, AdminLog.group_id == gid, AdminLog.action == 'BAN')} · Mutes: {db_count(AdminLog, AdminLog.group_id == gid, AdminLog.action == 'MUTE')}")
        else:
            flush_counters()
            with db() as s:
                total = s.execute(select(func.coalesce(func.sum(XP.messages), 0)).where(XP.group_id == gid)).scalar()
            text = f"📊 <b>STATISTICS</b>\nMessages tracked: {total}\nFilters: {len(get_filters(gid))} · Notes: {db_count(Note, Note.group_id == gid)}\nMod actions: {db_count(AdminLog, AdminLog.group_id == gid)}"
    except TelegramError as e:
        text = f"❌ Telegram: {h(e.message)}"
    return text, Kb([[back]])


@impl("groupinfo", "gstats", "gsettings")
async def cmd_groupinfo(update, ctx, name):
    gid = _gid_arg(update, ctx)
    if not gid:
        return await reply(update, f"Usage: <code>{h(META[name]['usage'])}</code>")
    if name == "gsettings":
        d = _load_group(gid)
        return await reply(update, f"⚙️ <b>{gid}</b> overrides:\n<pre>{h(json.dumps(d, indent=1, ensure_ascii=False)[:3500]) if d else 'defaults only'}</pre>")
    text, _ = await group_view(ctx, gid, "home" if name == "groupinfo" else "stats")
    await reply(update, text)


@impl("users", "userinfo")
async def cmd_users(update, ctx, name):
    if name == "userinfo":
        if not ctx.args or not ctx.args[0].isdigit():
            return await reply(update, "Usage: <code>/userinfo &lt;id&gt;</code>")
        uid = int(ctx.args[0])
        with db() as s:
            u = s.get(User, uid)
        if not u:
            return await reply(update, "❓ Unknown user.")
        return await reply(update, f"👤 {mention(uid)}\n🆔 <code>{uid}</code>\n@{u.username or '—'}\nDM started: {'yes' if u.started else 'no'}\nFirst seen: {fmt_ts(u.first_seen)}\nLast seen: {fmt_ts(u.last_seen)}\n"
                                   f"Warnings: {db_count(Warning, Warning.user_id == uid)} · Mod actions: {db_count(AdminLog, AdminLog.target_id == uid)}")
    with db() as s:
        rows = s.execute(select(User).order_by(User.last_seen.desc()).limit(20)).scalars().all()
    await reply(update, f"👥 <b>USERS</b> ({db_count(User)}; DM-reachable {db_count(User, User.started == True)})\n" +  # noqa: E712
                "\n".join(f"• {h(display(u.user_id))} <code>{u.user_id}</code>" for u in rows))


def logs_page(gid: int, page: int):
    with db() as s:
        q = select(AdminLog).order_by(AdminLog.ts.desc())
        if gid:
            q = q.where(AdminLog.group_id == gid)
        rows = s.execute(q.offset(page * 10).limit(11)).scalars().all()
    more = len(rows) > 10
    lines = [f"{fmt_ts(r.ts)} · <b>{r.action}</b> · {r.group_id} · by {r.executor_id} → {r.target_id} · {h((r.reason or '')[:40])}" for r in rows[:10]]
    nav = [Btn("⬅️", callback_data=f"lg:{gid}:{max(0, page - 1)}"), Btn("➡️", callback_data=f"lg:{gid}:{page + 1 if more else page}")]
    return f"📋 <b>ADMIN LOGS</b> (page {page + 1})\n" + ("\n".join(lines) or "Nothing logged."), Kb([nav, [Btn("⬅️ Back", callback_data=f"grp:{gid}:home" if gid else "own:home")]])


@impl("logs", "errors")
async def cmd_logs(update, ctx, name):
    if name == "errors":
        return await reply(update, "🐞 <b>RECENT ERRORS</b>\n<pre>" + h("\n\n".join(list(ERRORS)[-6:]) or "None")[:3500] + "</pre>")
    if ctx.args and ctx.args[0].lower() == "file" and Path("bot.log").exists():
        return await update.effective_message.reply_document(open("bot.log", "rb"))
    text, kb = logs_page(_gid_arg(update, ctx) or 0, 0)
    await reply(update, text, reply_markup=kb)


@impl("backup")
async def cmd_backup(update, ctx, name):
    if not _IS_SQLITE or update.effective_chat.type != ChatType.PRIVATE:
        return await reply(update, "💾 Backups are sent in private chat and only for SQLite databases.")
    src = DATABASE_URL.replace("sqlite:///", "")
    dst = f"backup_{int(time.time())}.db"
    a, b = sqlite3.connect(src), sqlite3.connect(dst)
    try:
        a.backup(b)
    finally:
        a.close()
        b.close()
    try:
        with open(dst, "rb") as f:
            await update.effective_message.reply_document(f, filename=dst, caption="💾 Database backup")
    finally:
        os.remove(dst)


@impl("globalsettings", "setglobal")
async def cmd_globalsettings(update, ctx, name):
    args = list(ctx.args or [])
    if name == "setglobal":
        if len(args) < 2:
            return await reply(update, "Usage: <code>/setglobal &lt;key&gt; &lt;value&gt;</code> (applies to groups without their own override)")
        key = args[0]
        try:
            if key in ("bot_enabled", "maintenance_mode"):
                bset(key, args[1].lower() in ("on", "true", "1"))
            elif key in DEFAULTS:
                bset("default:" + key, _coerce(key, args[1]))
            else:
                return await reply(update, "❓ Unknown key. See /globalsettings")
        except Exception as e:
            return await reply(update, f"❌ Invalid value ({h(e)}).")
        return await reply(update, f"✅ Global <code>{h(key)}</code> = <b>{h(args[1])}</b>")
    bget("x")
    over = {k[8:]: v for k, v in _BC.items() if k.startswith("default:")}
    await reply(update, f"🌐 <b>GLOBAL</b>\nbot_enabled: {bget('bot_enabled', True)}\nmaintenance_mode: {bget('maintenance_mode', False)}\n"
                        f"Default overrides:\n<pre>{h(json.dumps(over, indent=1)) if over else 'none'}</pre>\nKeys: <code>{' '.join(sorted(DEFAULTS))}</code>")


@impl("announce")
async def cmd_announce(update, ctx, name):
    args = list(ctx.args or [])
    gid = None
    if args and re.fullmatch(r"-?\d+", args[0]):
        gid, args = int(args[0]), args[1:]
    elif is_group(update.effective_chat):
        gid = update.effective_chat.id
    if not gid or not args:
        return await reply(update, f"Usage: <code>{h(META[name]['usage'])}</code>")
    await send_payload(ctx.bot, gid, {"text": " ".join(args)}, pin=False)
    await reply(update, "📢 Announcement sent.")


@impl("broadcast", "gbroadcast")
async def cmd_broadcast(update, ctx, name):
    msg, r = update.effective_message, update.effective_message.reply_to_message
    text = " ".join(ctx.args or [])
    if r:
        draft = {"kind": "copy", "chat": r.chat_id, "mid": r.message_id, "preview": (r.text or r.caption or "[media]")[:80]}
    elif text:
        draft = {"kind": "text", "text": text, "preview": text[:80]}
    else:
        return await reply(update, f"Usage: <code>{h(META[name]['usage'])}</code>")
    draft["owner"] = update.effective_user.id
    token = secrets.token_hex(4)
    _DRAFTS[token] = draft
    if name == "gbroadcast":
        text_, kb = bc_confirm(token, "groups")
        return await reply(update, text_, reply_markup=kb)
    await reply(update, f"📢 <b>BROADCAST</b>\n<i>{h(draft['preview'])}</i>\n\nChoose the audience:",
                reply_markup=Kb([[Btn("🏠 Groups only", callback_data=f"bc:{token}:t:groups"), Btn("👥 Users only", callback_data=f"bc:{token}:t:users")],
                                 [Btn("🌐 Groups + Users", callback_data=f"bc:{token}:t:all")], [Btn("❌ Cancel", callback_data=f"bc:{token}:x")]]))


def bc_targets(target: str) -> list[int]:
    ids: list[int] = []
    with db() as s:
        if target in ("groups", "all"):
            ids += s.execute(select(Group.group_id).where(Group.left == False, Group.enabled == True)).scalars().all()  # noqa: E712
        if target in ("users", "all"):
            ids += s.execute(select(User.user_id).where(User.started == True, User.is_bot == False)).scalars().all()  # noqa: E712
    return ids


def bc_confirm(token: str, target: str):
    n = len(bc_targets(target))
    return (f"⚠️ <b>CONFIRM BROADCAST</b>\n\nAudience: <b>{target}</b> ({n} chats)\n<i>{h(_DRAFTS[token]['preview'])}</i>\n\nUsers can only be reached if they have started the bot.",
            Kb([[Btn("🔴 CONFIRM", callback_data=f"bc:{token}:go:{target}"), Btn("❌ CANCEL", callback_data=f"bc:{token}:x")]]))


async def run_broadcast(ctx, q, draft: dict, target: str):
    ids = bc_targets(target)
    sent = failed = 0
    for i, cid in enumerate(ids, 1):
        for attempt in range(2):
            try:
                if draft["kind"] == "copy":
                    await ctx.bot.copy_message(cid, draft["chat"], draft["mid"])
                else:
                    body, kb = split_buttons(draft["text"])
                    await say(ctx.bot, cid, body, reply_markup=kb)
                sent += 1
                break
            except RetryAfter as e:
                await asyncio.sleep(e.retry_after + 1)
            except TelegramError:
                failed += 1
                break
        else:
            failed += 1
        await asyncio.sleep(0.05)  # ~20 msg/s, below Telegram's ~30 msg/s limit
        if i % 25 == 0:
            await edit(q, f"📤 Broadcasting… {i}/{len(ids)}")
    with db() as s:
        s.add(BroadcastLog(owner_id=draft["owner"], target=target, total=len(ids), sent=sent, failed=failed, preview=draft["preview"], ts=time.time()))
    await edit(q, f"✅ <b>BROADCAST DONE</b>\nSent: {sent}\nFailed: {failed}\nTotal: {len(ids)}")


# =========================================
# CALLBACK HANDLERS
# =========================================
async def edit(q, text: str, kb=None):
    try:
        await q.edit_message_text(text[:4000], parse_mode=ParseMode.HTML, reply_markup=kb, link_preview_options=NOPREV)
    except BadRequest as e:
        if "not modified" not in str(e).lower():
            raise


async def _owner_only(q) -> bool:
    if q.from_user.id != OWNER_ID or not OWNER_ID:
        await q.answer("🚫 Owner only.", show_alert=True)
        return False
    return True


async def _admin_only(q, ctx, gid: int, level: int = 2) -> bool:
    if await get_role(ctx.bot, gid, q.from_user.id) < level:
        await q.answer("🚫 You don't have permission for this.", show_alert=True)
        return False
    return True


async def on_callback(update: Update, ctx):
    q = update.callback_query
    data, uid = q.data or "", q.from_user.id
    p = data.split(":")
    track(update)
    if uid != OWNER_ID and not bot_online():
        return await q.answer("🔴 Ivy is in maintenance mode.", show_alert=True)
    kind = p[0]
    if kind == "cc":
        await q.answer()
        text, kb = cc_home() if p[1] == "home" else cc_cat(int(p[2]), int(p[3]))
        return await edit(q, text, kb)
    if kind == "cf":
        item = _CONF.get(p[1])
        if not item or item[3] < time.time():
            _CONF.pop(p[1], None)
            return await q.answer("⌛ Expired.", show_alert=True)
        if item[0] != uid:
            return await q.answer("🚫 This confirmation isn't yours.", show_alert=True)
        _CONF.pop(p[1])
        await q.answer()
        if p[2] != "y":
            return await edit(q, "❌ Cancelled.")
        return await edit(q, await item[1](ctx, *item[2]))
    if kind == "vf":
        gid, target = int(p[1]), int(p[2])
        if uid != target:
            return await q.answer("This button isn't for you.", show_alert=True)
        try:
            await restore_perms(ctx.bot, gid, uid)
        except TelegramError as e:
            log.info("verify restore failed: %s", e)
        with db() as s:
            v = s.execute(select(Verification).where(Verification.group_id == gid, Verification.user_id == uid)).scalar()
            if v:
                v.verified = True
        _UNVER.discard((gid, uid))
        await q.answer("✅ Verified!")
        try:
            await q.message.delete()
        except TelegramError:
            pass
        await send_welcome(ctx, q.message.chat, q.from_user)
        return
    if kind == "uw":
        gid = int(p[1])
        if not await _admin_only(q, ctx, gid, 1):
            return
        with db() as s:
            s.execute(delete(Warning).where(Warning.id == int(p[2]), Warning.group_id == gid))
        await alog(ctx.bot, gid, "UNWARN", uid, 0, "via button")
        await q.answer("Removed")
        return await edit(q, "✅ Warning removed.")
    if kind in ("sp", "sx", "lk"):
        gid = int(p[1])
        if not await _admin_only(q, ctx, gid):
            return
        if kind == "lk":
            m, a = get_locks(gid).get(p[2], (False, False))
            new = (True, False) if not m else (True, True) if not a else (False, False)
            set_lock(gid, p[2], member=new[0], admin=new[1])
            await alog(ctx.bot, gid, "LOCKADMIN" if new[1] else "LOCK" if new[0] else "UNLOCK", uid, 0, p[2])
            await q.answer()
            text, kb = locks_view(gid, back=True)
            return await edit(q, text, kb)
        section = p[2] if kind == "sp" else p[4]
        if kind == "sx":
            key, op = p[2], p[3]
            meta = next((it for it in SECTIONS[section][1] if it[0] == key), None)
            if meta and op != "n":
                if meta[1] == "b":
                    val = not gget(gid, key)
                    if key == "raidmode":
                        await set_raid(ctx.bot, gid, val)
                    else:
                        gset(gid, key, val)
                elif meta[1] == "c":
                    opts = meta[2]
                    gset(gid, key, opts[(opts.index(gget(gid, key)) + 1) % len(opts)] if gget(gid, key) in opts else opts[0])
                else:
                    step, lo, hi = meta[2:5]
                    gset(gid, key, max(lo, min(hi, gget(gid, key) + (step if op == "+" else -step))))
                await alog(ctx.bot, gid, "SECURITY", uid, 0, f"{key} via panel")
        await q.answer()
        text, kb = panel(gid, section)
        return await edit(q, text, kb)
    # ---- owner-only below ----
    if not await _owner_only(q):
        return
    await q.answer()
    if kind == "own":
        if p[1] == "home":
            return await edit(q, *owner_panel())
        back = Kb([[Btn("⬅️ Back", callback_data="own:home")]])
        if p[1] == "users":
            return await edit(q, f"👥 <b>USERS</b>\nKnown: {db_count(User)} · DM-reachable: {db_count(User, User.started == True)}\nUse /users or /userinfo &lt;id&gt;", back)  # noqa: E712
        if p[1] == "bc":
            return await edit(q, "📢 <b>BROADCAST</b>\nSend <code>/broadcast &lt;text&gt;</code> or reply to any message with /broadcast (media supported). You'll choose the audience and confirm before anything is sent.", back)
        if p[1] == "set":
            return await edit(q, f"⚙️ <b>GLOBAL SETTINGS</b>\nbot_enabled: {bget('bot_enabled', True)}\nmaintenance_mode: {bget('maintenance_mode', False)}\nUse /globalsettings and /setglobal.", back)
        if p[1] == "stats":
            flush_counters()
            with db() as s:
                msgs = s.execute(select(func.coalesce(func.sum(XP.messages), 0))).scalar()
            return await edit(q, f"📊 <b>STATISTICS</b>\nMessages tracked: {msgs}\nAdmin actions: {db_count(AdminLog)}\nBroadcasts: {db_count(BroadcastLog)}\nScheduled (pending): {db_count(ScheduledTask, ScheduledTask.done == False)}", back)  # noqa: E712
        if p[1] == "maint":
            on = not bget("maintenance_mode", False)
            return await edit(q, f"⚠️ <b>CONFIRM</b>\n\n{'Enable' if on else 'Disable'} maintenance mode?", confirm_kb(uid, act_maint, on))
    elif kind == "ogl":
        return await edit(q, *groups_page(int(p[1])))
    elif kind == "grp":
        gid = int(p[1])
        if p[2] == "tog":
            with db() as s:
                g = s.get(Group, gid)
                on = not (g.enabled if g else True)
            return await edit(q, f"⚠️ <b>CONFIRM</b>\n\n{'Enable' if on else 'Disable'} Ivy in <code>{gid}</code>?", confirm_kb(uid, act_group, gid, on))
        return await edit(q, *await group_view(ctx, gid, p[2]))
    elif kind == "lg":
        return await edit(q, *logs_page(int(p[1]), max(0, int(p[2]))))
    elif kind == "bc":
        draft = _DRAFTS.get(p[1])
        if not draft or draft["owner"] != uid:
            return await edit(q, "⌛ This broadcast draft expired.")
        if p[2] == "x":
            _DRAFTS.pop(p[1], None)
            return await edit(q, "❌ Broadcast cancelled.")
        if p[2] == "t":
            return await edit(q, *bc_confirm(p[1], p[3]))
        if p[2] == "go":
            _DRAFTS.pop(p[1], None)
            await edit(q, "📤 Broadcasting…")
            bg(run_broadcast(ctx, q, draft, p[3]))


# =========================================
# ERROR HANDLING
# =========================================
_LAST_ALERT: dict = {}


async def on_error(update, ctx):
    err = ctx.error
    if isinstance(err, (NetworkError, TimedOut)):
        log.warning("Network issue: %s", err)
        return
    tb = "".join(traceback.format_exception(type(err), err, err.__traceback__))
    log.error("Unhandled exception: %s", tb)
    ERRORS.append(f"{datetime.now().strftime('%m-%d %H:%M')} {type(err).__name__}: {err}\n{tb[-600:]}")
    if isinstance(update, Update) and update.effective_chat and update.effective_chat.type == ChatType.PRIVATE and update.effective_user and update.effective_user.id != OWNER_ID:
        try:
            await update.effective_message.reply_text("⚠️ Something went wrong. Please try again later.")
        except TelegramError:
            pass
    key = type(err).__name__
    if OWNER_ID and time.time() - _LAST_ALERT.get(key, 0) > 60:  # critical error alert to the owner (rate-limited)
        _LAST_ALERT[key] = time.time()
        try:
            await ctx.bot.send_message(OWNER_ID, f"🚨 <b>Error</b>: <code>{h(key)}</code>\n{h(str(err)[:300])}\nSee /errors", parse_mode=ParseMode.HTML)
        except TelegramError:
            pass


# =========================================
# STARTUP
# =========================================
async def post_init(app: Application):
    global APP
    APP = app
    SCHED.start()
    restore_tasks()
    SCHED.add_job(flush_counters, "interval", seconds=30, id="flush", replace_existing=True)
    with db() as s:
        for gid, uid in s.execute(select(Verification.group_id, Verification.user_id).where(Verification.verified == False)).all():  # noqa: E712
            _UNVER.add((gid, uid))
    core = ["start", "help", "command", "rules", "notes", "warnings", "rank", "leaderboard", "balance", "daily", "info", "id", "admins", "report" if False else "locks", "settings"]
    try:
        await app.bot.set_my_commands([BotCommand(c, META[c]["desc"][:255]) for c in core])
        await app.bot.send_message(OWNER_ID, f"🟢 <b>{h(BOT_NAME)}</b> v{VERSION} started — {len(META)} commands.", parse_mode=ParseMode.HTML)
    except TelegramError as e:
        log.warning("Startup notice failed: %s (open the bot and press /start once)", e)


async def post_shutdown(app: Application):
    flush_counters()
    if SCHED.running:
        SCHED.shutdown(wait=False)


def main():
    setup_logging()
    if not BOT_TOKEN or not OWNER_ID:
        sys.exit("BOT_TOKEN and OWNER_ID must be set in .env (see .env.example).")
    init_db()
    build_registry()
    app = Application.builder().token(BOT_TOKEN).concurrent_updates(True).post_init(post_init).post_shutdown(post_shutdown).build()
    for name in META:
        app.add_handler(CommandHandler(name, make_handler(name), filters=filters.UpdateType.MESSAGE))
    app.add_handler(CallbackQueryHandler(on_callback))
    app.add_handler(MessageHandler(filters.StatusUpdate.NEW_CHAT_MEMBERS, on_new_members))
    app.add_handler(MessageHandler(filters.StatusUpdate.LEFT_CHAT_MEMBER, on_left_member))
    app.add_handler(ChatMemberHandler(on_my_chat_member, ChatMemberHandler.MY_CHAT_MEMBER))
    app.add_handler(MessageHandler(filters.ALL & ~filters.COMMAND & ~filters.StatusUpdate.ALL, on_message), group=1)
    app.add_error_handler(on_error)
    log.info("%s v%s starting", BOT_NAME, VERSION)
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
