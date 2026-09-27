# -*- coding: utf-8 -*-
"""Web dashboard + key authentication for the LW worker."""
import asyncio
import hashlib
import json
import os
import secrets
import time
from pathlib import Path
from typing import Dict, List, Any, Optional
from aiohttp import web

BASE_DIR = Path(__file__).resolve().parent
ACCOUNTS_FILE = BASE_DIR / "accounts.json"
KEYS_FILE = BASE_DIR / "keys.json"
TEMPLATE_PATH = BASE_DIR / "templates" / "index.html"
DEFAULT_ADMIN_KEY = os.getenv("ADMIN_KEY", "nghuy29122011")
SESSION_TTL = 60 * 60 * 24 * 7
SESSIONS: Dict[str, Dict[str, Any]] = {}


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _load_json(path: Path, fallback):
    try:
        if path.exists():
            with path.open("r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return fallback


def _save_json(path: Path, data):
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    tmp.replace(path)


def _ensure_keys():
    data = _load_json(KEYS_FILE, [])
    if not isinstance(data, list):
        data = []
    # Generated keys only. The master key is deliberately not written to disk.
    return data


def _new_key() -> str:
    return "LW-" + secrets.token_urlsafe(18).replace("-", "").replace("_", "")[:24].upper()


def _session(request: web.Request):
    sid = request.cookies.get("lw_session")
    if not sid:
        return None
    item = SESSIONS.get(sid)
    if not item:
        return None
    if item["expires"] < time.time():
        SESSIONS.pop(sid, None)
        return None
    return item


def _require(request: web.Request, admin: bool = False):
    session = _session(request)
    if not session:
        return None, web.json_response({"status": "error", "error": "AUTH_REQUIRED"}, status=401)
    if admin and session.get("role") != "admin":
        return None, web.json_response({"status": "error", "error": "ADMIN_REQUIRED"}, status=403)
    return session, None


class BotState:
    def __init__(self):
        self.accounts: Dict[str, Dict[str, Any]] = {}
        self.logs: List[Dict[str, Any]] = []
        self.max_logs = 200
        self.total_matches = 0
        self.total_gained_exp = 0
        self.start_time = time.time()
        self.account_workers: Dict[str, asyncio.Task] = {}
        self.refresh_callbacks: Dict[str, Any] = {}
        self.account_credentials: Dict[str, Dict[str, Any]] = {}

    def log(self, message: str, level: str = "info", uid: Optional[str] = None):
        self.logs.append({"time": time.strftime("%H:%M:%S"), "level": level, "message": message, "uid": uid})
        if len(self.logs) > self.max_logs:
            self.logs.pop(0)

    def register_account(self, uid: str, nickname: str, region: str, level: int, exp: int, likes: int = 0):
        uid_str = str(uid)
        if uid_str not in self.accounts:
            self.accounts[uid_str] = {
                "uid": uid_str, "nickname": nickname or f"Player_{uid_str[:6]}",
                "region": region or "BD", "level": level or 1,
                "initial_exp": exp, "current_exp": exp, "gained_exp": 0,
                "likes": likes or 0, "status": "ONLINE", "matches_played": 0,
                "active_matches": 0, "last_match_time": None,
                "last_updated": time.strftime("%H:%M:%S")
            }
        else:
            acc = self.accounts[uid_str]
            if nickname: acc["nickname"] = nickname
            if region: acc["region"] = region
            if level: acc["level"] = level
            acc["current_exp"] = exp
            acc["gained_exp"] = max(0, exp - acc["initial_exp"])
            acc["likes"] = likes
            acc["status"] = "ONLINE"
            acc["last_updated"] = time.strftime("%H:%M:%S")
        self.recalc_totals()

    def update_exp(self, uid: str, current_exp: int, level: Optional[int] = None):
        uid_str = str(uid)
        if uid_str in self.accounts:
            acc = self.accounts[uid_str]
            old_exp = acc["current_exp"]
            acc["current_exp"] = current_exp
            if level is not None and level > 0: acc["level"] = level
            acc["gained_exp"] = max(0, current_exp - acc["initial_exp"])
            acc["last_updated"] = time.strftime("%H:%M:%S")
            diff = current_exp - old_exp
            if diff > 0:
                self.log(f"{acc['nickname']} ({uid_str}) +{diff} EXP | Total +{acc['gained_exp']}", "success", uid_str)
            self.recalc_totals()

    def update_status(self, uid: str, status: str, active_matches: Optional[int] = None):
        uid_str = str(uid)
        if uid_str in self.accounts:
            self.accounts[uid_str]["status"] = status
            if active_matches is not None: self.accounts[uid_str]["active_matches"] = active_matches
            self.accounts[uid_str]["last_updated"] = time.strftime("%H:%M:%S")

    def increment_match(self, uid: str):
        uid_str = str(uid)
        self.total_matches += 1
        if uid_str in self.accounts:
            acc = self.accounts[uid_str]
            acc["matches_played"] += 1
            acc["last_match_time"] = time.strftime("%H:%M:%S")
            acc["last_updated"] = time.strftime("%H:%M:%S")
            self.log(f"{acc['nickname']} finished Match #{acc['matches_played']}", "info", uid_str)

    def recalc_totals(self):
        self.total_gained_exp = sum(acc.get("gained_exp", 0) for acc in self.accounts.values())


bot_state = BotState()


async def handle_index(request):
    return web.FileResponse(TEMPLATE_PATH)


async def handle_login(request):
    try:
        data = await request.json()
        key = str(data.get("key", "")).strip()
        if not key:
            return web.json_response({"status": "error", "error": "Vui lòng nhập key."}, status=400)
        role = None
        if secrets.compare_digest(key, DEFAULT_ADMIN_KEY):
            role = "admin"
        else:
            h = _hash(key)
            for item in _ensure_keys():
                if item.get("hash") == h and not item.get("revoked", False):
                    role = "user"
                    break
        if not role:
            return web.json_response({"status": "error", "error": "Key không hợp lệ hoặc đã bị thu hồi."}, status=401)
        sid = secrets.token_urlsafe(32)
        SESSIONS[sid] = {"role": role, "expires": time.time() + SESSION_TTL}
        resp = web.json_response({"status": "ok", "role": role})
        resp.set_cookie("lw_session", sid, max_age=SESSION_TTL, httponly=True, samesite="Lax", path="/")
        return resp
    except Exception as e:
        return web.json_response({"status": "error", "error": str(e)}, status=400)


async def handle_logout(request):
    sid = request.cookies.get("lw_session")
    if sid: SESSIONS.pop(sid, None)
    resp = web.json_response({"status": "ok"})
    resp.del_cookie("lw_session", path="/")
    return resp


async def handle_auth(request):
    session = _session(request)
    if not session:
        return web.json_response({"authenticated": False})
    return web.json_response({"authenticated": True, "role": session["role"], "expires": int(session["expires"])})


async def handle_get_keys(request):
    _, err = _require(request, admin=True)
    if err: return err
    data = _ensure_keys()
    safe = [{"id": x.get("id"), "label": x.get("label", ""), "created_at": x.get("created_at"), "revoked": x.get("revoked", False)} for x in data]
    return web.json_response({"status": "ok", "keys": safe})


async def handle_create_key(request):
    _, err = _require(request, admin=True)
    if err: return err
    try:
        data = await request.json()
        label = str(data.get("label", "")).strip()[:50]
        key = _new_key()
        keys = _ensure_keys()
        keys.append({"id": secrets.token_hex(8), "hash": _hash(key), "label": label, "created_at": time.strftime("%Y-%m-%d %H:%M:%S"), "revoked": False})
        _save_json(KEYS_FILE, keys)
        bot_state.log(f"Created access key{(' for ' + label) if label else ''}.", "success")
        return web.json_response({"status": "ok", "key": key, "label": label})
    except Exception as e:
        return web.json_response({"status": "error", "error": str(e)}, status=400)


async def handle_revoke_key(request):
    _, err = _require(request, admin=True)
    if err: return err
    try:
        data = await request.json(); key_id = str(data.get("id", "")).strip()
        keys = _ensure_keys(); found = False
        for item in keys:
            if item.get("id") == key_id:
                item["revoked"] = True; found = True; break
        if not found: return web.json_response({"status": "error", "error": "Không tìm thấy key."}, status=404)
        _save_json(KEYS_FILE, keys)
        bot_state.log(f"Revoked access key {key_id}.", "warning")
        return web.json_response({"status": "ok"})
    except Exception as e:
        return web.json_response({"status": "error", "error": str(e)}, status=400)


async def handle_get_stats(request):
    _, err = _require(request)
    if err: return err
    accounts_data = list(bot_state.accounts.values())
    accounts_data.sort(key=lambda x: x.get("gained_exp", 0), reverse=True)
    return web.json_response({
        "total_accounts": len(bot_state.accounts), "total_matches": bot_state.total_matches,
        "total_gained_exp": bot_state.total_gained_exp, "accounts": accounts_data,
        "logs": bot_state.logs[-60:], "uptime": int(time.time() - bot_state.start_time)
    })


async def handle_add_account(request):
    _, err = _require(request)
    if err: return err
    try:
        data = await request.json(); existing = _load_json(ACCOUNTS_FILE, [])
        if not isinstance(existing, list): existing = []
        if "uid" in data and "password" in data:
            uid, pwd = str(data["uid"]).strip(), str(data["password"]).strip()
            if not uid or not pwd: return web.json_response({"status":"error","error":"UID và Password bắt buộc."}, status=400)
            existing = [a for a in existing if str(a.get("uid")) != uid]; existing.append({"uid": uid, "password": pwd})
            log_name = uid
        elif "token" in data:
            token = str(data["token"]).strip()
            if not token: return web.json_response({"status":"error","error":"Token bắt buộc."}, status=400)
            existing = [a for a in existing if a.get("token") != token]; existing.append({"token": token}); log_name = "Token"
        else: return web.json_response({"status":"error","error":"Dữ liệu không hợp lệ."}, status=400)
        _save_json(ACCOUNTS_FILE, existing)
        bot_state.log(f"Added account: {log_name}", "success")
        cb = bot_state.refresh_callbacks.get("on_account_added")
        if cb: asyncio.create_task(cb(data))
        return web.json_response({"status":"ok"})
    except Exception as e:
        return web.json_response({"status":"error","error":str(e)}, status=400)


async def handle_delete_account(request):
    _, err = _require(request)
    if err: return err
    try:
        data = await request.json(); uid = str(data.get("uid", "")).strip()
        existing = _load_json(ACCOUNTS_FILE, [])
        _save_json(ACCOUNTS_FILE, [a for a in existing if str(a.get("uid")) != uid])
        if uid in bot_state.accounts: del bot_state.accounts[uid]
        if uid in bot_state.account_workers:
            bot_state.account_workers[uid].cancel(); del bot_state.account_workers[uid]
        bot_state.log(f"Removed account {uid}.", "warning", uid)
        return web.json_response({"status":"ok"})
    except Exception as e:
        return web.json_response({"status":"error","error":str(e)}, status=400)


async def handle_refresh_account(request):
    _, err = _require(request)
    if err: return err
    try:
        data = await request.json(); uid = str(data.get("uid", "")).strip()
        cb = bot_state.refresh_callbacks.get("on_refresh_account")
        if cb: asyncio.create_task(cb(uid))
        return web.json_response({"status":"ok"})
    except Exception as e:
        return web.json_response({"status":"error","error":str(e)}, status=400)


async def start_web_dashboard(host="0.0.0.0", port=None):
    port = int(port or os.getenv("PORT", "10000"))
    app = web.Application()
    app.router.add_get("/", handle_index)
    app.router.add_get("/api/auth", handle_auth)
    app.router.add_post("/api/login", handle_login)
    app.router.add_post("/api/logout", handle_logout)
    app.router.add_get("/api/stats", handle_get_stats)
    app.router.add_post("/api/account/add", handle_add_account)
    app.router.add_post("/api/account/delete", handle_delete_account)
    app.router.add_post("/api/account/refresh", handle_refresh_account)
    app.router.add_get("/api/keys", handle_get_keys)
    app.router.add_post("/api/keys/create", handle_create_key)
    app.router.add_post("/api/keys/revoke", handle_revoke_key)
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    site = web.TCPSite(runner, host, port)
    await site.start()
    print(f"[+] Web Dashboard running on 0.0.0.0:{port}")
