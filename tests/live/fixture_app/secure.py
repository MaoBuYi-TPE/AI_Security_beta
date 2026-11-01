"""修補版（secure）handler，即 ground truth 的負例（T30）。

每個 handler 都以參數化查詢、輸入驗證、物件層級授權與安全的預設行為，修正 insecure.py
對應案例的弱點。這裡是修補差異（案例表的「修補差異」欄）的實作。
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from .common import home, me
from .helpers import (
    REDIRECT_ALLOWLIST,
    escape,
    html_response,
    json_response,
    parse_int,
    text_response,
)
from .model import Request, Response
from .store import State

# 修補版登入成功時的安全 cookie（案例 FX-07）。
_SECURE_COOKIE = "session={token}; HttpOnly; Secure; SameSite=Strict; Path=/"


def search(req: Request, state: State) -> Response:
    query = req.query.get("q", "")
    rows = state.query("SELECT id, item, total_cents FROM orders WHERE item = ?", (query,))
    return json_response([{"id": row[0], "item": row[1], "total_cents": row[2]} for row in rows])


def greet(req: Request, state: State) -> Response:
    name = req.query.get("name", "")
    return html_response(f"<!doctype html><html><body><p>hello {escape(name)}</p></body></html>")


def login(req: Request, state: State) -> Response:
    username = req.form.get("username", "")
    password = req.form.get("password", "")
    rows = state.query(
        "SELECT username FROM users WHERE username = ? AND password = ?",
        (username, password),
    )
    if not rows:
        return json_response({"status": "fail"}, status=401)
    token = state.token_for_user(str(rows[0][0])) or ""
    cookie = _SECURE_COOKIE.format(token=token)
    return json_response({"status": "success"}, headers=(("Set-Cookie", cookie),))


def go(req: Request, state: State) -> Response:
    target = req.query.get("next", "/")
    if target not in REDIRECT_ALLOWLIST:
        return text_response("bad redirect target", status=400)
    return Response(status=302, headers=(("Location", target),))


def backup(req: Request, state: State) -> Response:
    return text_response("not found", status=404)


def users_list(req: Request, state: State) -> Response:
    rows = state.query("SELECT id, username, email FROM users")
    return json_response([{"id": row[0], "username": row[1], "email": row[2]} for row in rows])


def users_create(req: Request, state: State) -> Response:
    payload = _json_object(req.body)
    if payload is None:
        return text_response("invalid body", status=400)
    username = payload.get("username")
    password = payload.get("password")
    if not isinstance(username, str) or not username or not isinstance(password, str):
        return text_response("username and password are required", status=400)
    new_id = _next_user_id(state)
    # is_admin 一律 0：忽略 body 傳入的值（修補 mass assignment）。
    with state.lock:
        state.db.execute(
            "INSERT INTO users (id, username, password, is_admin, email, secret_note) "
            "VALUES (?, ?, ?, 0, ?, '')",
            (new_id, username, password, f"{username}@lab.test"),
        )
        state.db.commit()
    return json_response({"id": new_id, "username": username, "is_admin": False}, status=201)


def user_get(req: Request, state: State) -> Response:
    user_id = parse_int(req.params.get("id"))
    if user_id is None:
        return text_response("invalid id", status=400)
    rows = state.query("SELECT id, username, email FROM users WHERE id = ?", (user_id,))
    if not rows:
        return text_response("not found", status=404)
    row = rows[0]
    # 符合 OpenAPI 宣告的 schema：id 整數、username/email 字串，不多出欄位（修補 C3）。
    return json_response({"id": row[0], "username": row[1], "email": row[2]})


def order_get(req: Request, state: State) -> Response:
    user = state.user_for_token(req.bearer())
    if user is None:
        return json_response({"status": "fail"}, status=401)
    order_id = parse_int(req.params.get("id"))
    if order_id is None:
        return text_response("invalid id", status=400)
    rows = state.query("SELECT id, owner, item, total_cents FROM orders WHERE id = ?", (order_id,))
    if not rows or rows[0][1] != user:
        # 物件層級授權：不是自己的 order 一律當作不存在（修補 BOLA）。
        return text_response("not found", status=404)
    row = rows[0]
    return json_response({"id": row[0], "owner": row[1], "item": row[2], "total_cents": row[3]})


def order_put(req: Request, state: State) -> Response:
    # OpenAPI 沒有宣告 PUT：回 405（修補 C5）。
    return text_response("method not allowed", status=405, headers=(("Allow", "GET"),))


def user_by_name(req: Request, state: State) -> Response:
    username = req.params.get("username", "")
    rows = state.query("SELECT id, username, email FROM users WHERE username = ?", (username,))
    if not rows:
        return text_response("not found", status=404)
    row = rows[0]
    return json_response({"id": row[0], "username": row[1], "email": row[2]})


def _json_object(body: bytes) -> dict[str, Any] | None:
    try:
        payload = json.loads(body or b"{}")
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    return payload


def _next_user_id(state: State) -> int:
    rows = state.query("SELECT COALESCE(MAX(id), 0) FROM users")
    return int(rows[0][0]) + 1


HANDLERS: dict[str, Callable[[Request, State], Response]] = {
    "home": home,
    "me": me,
    "search": search,
    "greet": greet,
    "login": login,
    "go": go,
    "backup": backup,
    "users_list": users_list,
    "users_create": users_create,
    "user_get": user_get,
    "order_get": order_get,
    "order_put": order_put,
    "user_by_name": user_by_name,
}
