"""弱點版（insecure）handler，即 ground truth 的正例（T30）。

每個 handler 刻意實作 cases.py 登錄的弱點，供掃描器量測。只在隔離的 lab_net 上執行。
SQL 以字串拼接（ruff S608 於 pyproject 對本檔忽略，因為這正是要量測的 SQL 注入）；未處理
的例外故意上拋，由外殼回 500（契約/健壯性案例 C1/C2/C4/C5）。
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable

from .common import home, me
from .helpers import json_response, text_response
from .model import Request, Response
from .store import State

# 弱點版登入成功時的不安全 cookie（案例 FX-07：沒有 HttpOnly/Secure/SameSite）。
_INSECURE_COOKIE = "session={token}; Path=/"


def search(req: Request, state: State) -> Response:
    # FX-01 SQLi + FX-04 錯誤訊息洩漏：q 直接拼接進 SQL，錯誤時回傳例外訊息。
    query = req.query.get("q", "")
    sql = f"SELECT id, item, total_cents FROM orders WHERE item = '{query}'"
    try:
        rows = state.query(sql)
    except sqlite3.Error as error:
        return text_response(f"query failed: {error}", status=500)
    return json_response([{"id": row[0], "item": row[1], "total_cents": row[2]} for row in rows])


def greet(req: Request, state: State) -> Response:
    # FX-02 反射型 XSS：name 未轉義直接寫進 HTML。
    name = req.query.get("name", "")
    return Response(
        status=200,
        body=f"<!doctype html><html><body><p>hello {name}</p></body></html>".encode(),
        content_type="text/html; charset=utf-8",
    )


def login(req: Request, state: State) -> Response:
    # FX-03 表單 SQLi + FX-07 不安全 cookie。
    username = req.form.get("username", "")
    password = req.form.get("password", "")
    sql = f"SELECT username FROM users WHERE username = '{username}' AND password = '{password}'"
    try:
        rows = state.query(sql)
    except sqlite3.Error as error:
        return text_response(f"login failed: {error}", status=500)
    if not rows:
        return json_response({"status": "fail"}, status=401)
    token = state.token_for_user(str(rows[0][0])) or ""
    cookie = _INSECURE_COOKIE.format(token=token)
    return json_response({"status": "success"}, headers=(("Set-Cookie", cookie),))


def go(req: Request, state: State) -> Response:
    # FX-08 開放轉址：next 不驗證，任意目的地都轉出去。
    target = req.query.get("next", "/")
    return Response(status=302, headers=(("Location", target),))


def backup(req: Request, state: State) -> Response:
    # FX-09 敏感檔案暴露：回傳含帳密的傾印內容。
    rows = state.query("SELECT username, password FROM users")
    dump = "\n".join(f"{row[0]}:{row[1]}" for row in rows)
    return text_response(f"-- users backup --\n{dump}\n", status=200)


def users_list(req: Request, state: State) -> Response:
    # FX-12 過度資料暴露：回傳 password 與 secret_note。
    rows = state.query("SELECT id, username, email, password, secret_note FROM users")
    return json_response(
        [
            {
                "id": row[0],
                "username": row[1],
                "email": row[2],
                "password": row[3],
                "secret_note": row[4],
            }
            for row in rows
        ]
    )


def users_create(req: Request, state: State) -> Response:
    # FX-11 mass assignment（is_admin 直接取自 body）；C2/C4/C6 的壞 body 上拋例外 -> 500。
    payload = json.loads(req.body or b"{}")
    username = payload["username"]
    password = payload.get("password", "")
    is_admin = 1 if payload.get("is_admin") else 0
    new_id = _next_user_id(state)
    with state.lock:
        state.db.execute(
            "INSERT INTO users (id, username, password, is_admin, email, secret_note) "
            "VALUES (?, ?, ?, ?, ?, '')",
            (new_id, username, password, is_admin, f"{username}@lab.test"),
        )
        state.db.commit()
    return json_response(
        {"id": new_id, "username": username, "is_admin": bool(is_admin)}, status=201
    )


def user_get(req: Request, state: State) -> Response:
    # C3 回應不符 schema：多出 password、is_admin 欄位，id 以字串回傳。
    user_id = int(req.params["id"])
    rows = state.query(
        "SELECT id, username, email, password, is_admin FROM users WHERE id = ?", (user_id,)
    )
    if not rows:
        return text_response("not found", status=404)
    row = rows[0]
    return json_response(
        {
            "id": str(row[0]),
            "username": row[1],
            "email": row[2],
            "password": row[3],
            "is_admin": bool(row[4]),
        }
    )


def order_get(req: Request, state: State) -> Response:
    # FX-10 BOLA：帶 token 即可讀任一 order，不檢查擁有者；C1 非整數 id 上拋 -> 500。
    if state.user_for_token(req.bearer()) is None:
        return json_response({"status": "fail"}, status=401)
    order_id = int(req.params["id"])
    rows = state.query("SELECT id, owner, item, total_cents FROM orders WHERE id = ?", (order_id,))
    if not rows:
        return text_response("not found", status=404)
    row = rows[0]
    return json_response({"id": row[0], "owner": row[1], "item": row[2], "total_cents": row[3]})


def order_put(req: Request, state: State) -> Response:
    # C5 未文件化的 method：假設 body 有欄位，缺少時上拋 -> 500。
    payload = json.loads(req.body or b"{}")
    return json_response({"id": int(req.params["id"]), "total_cents": payload["total_cents"]})


def user_by_name(req: Request, state: State) -> Response:
    # FX-PB-01 path 參數 SQLi（strict-1 下 guard 以 PATH_AMBIGUOUS 擋下探測）。
    username = req.params.get("username", "")
    sql = f"SELECT id, username, email FROM users WHERE username = '{username}'"
    try:
        rows = state.query(sql)
    except sqlite3.Error as error:
        return text_response(f"query failed: {error}", status=500)
    if not rows:
        return text_response("not found", status=404)
    row = rows[0]
    return json_response({"id": row[0], "username": row[1], "email": row[2]})


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
