"""兩個模式共用的 handler（T30）：首頁與 /me preflight，行為與模式無關。

全域的模式差異（缺安全 header，案例 FX-05；CORS 萬用字元，案例 FX-06）由 app 外殼依 mode 套用，
不在個別 handler 裡。
"""

from __future__ import annotations

from .helpers import html_response, json_response
from .model import Request, Response
from .store import State

# 首頁放上範圍內的連結與表單，讓 traditional spider 走得到各 web 端點。
HOME = """<!doctype html><html><head><title>fixture app</title></head><body>
<h1>lab fixture</h1>
<ul>
<li><a href="/search?q=widget">search</a></li>
<li><a href="/greet?name=friend">greet</a></li>
<li><a href="/go?next=/search">go</a></li>
<li><a href="/backup.sql">backup</a></li>
</ul>
<form action="/login" method="post">
<input name="username"><input name="password" type="password">
<input type="submit">
</form>
</body></html>"""


def home(req: Request, state: State) -> Response:
    return html_response(HOME)


def me(req: Request, state: State) -> Response:
    """auth preflight：帶有效 bearer token 回 success，否則 401（docs §9 的保護端點）。"""
    user = state.user_for_token(req.bearer())
    if user is None:
        return json_response({"status": "fail"}, status=401)
    return json_response({"status": "success", "username": user})
