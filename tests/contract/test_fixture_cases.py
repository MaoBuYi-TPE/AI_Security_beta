"""T30：以純函式 handle() 驗證 fixture app 的每個 ground truth 案例（不連網）。

弱點版（insecure）呈現 cases.py 登錄的弱點（正例），修補版（secure）修正（負例）。這是
§5.2 的「依程式測試標記正/負例」的程式依據，也讓案例登錄表與實作不會各走各的。
平台阻擋案例（FX-PB-01）在這裡直接呼叫 handler、不經 guard，證明弱點在 app 層存在；live
測試才量 guard 的 PATH_AMBIGUOUS。
"""

from __future__ import annotations

from tests.live.fixture_app import cases
from tests.live.fixture_app.app import handle
from tests.live.fixture_app.insecure import HANDLERS as INSECURE
from tests.live.fixture_app.model import Mode, Request, Response
from tests.live.fixture_app.routes import HANDLER_KEYS, ROUTES
from tests.live.fixture_app.secure import HANDLERS as SECURE
from tests.live.fixture_app.store import CANARY_BOB, State, new_state

ALICE = "alice-token"


def req(
    method: str,
    path: str,
    *,
    query: dict[str, str] | None = None,
    form: dict[str, str] | None = None,
    body: bytes = b"",
    bearer: str | None = None,
) -> Request:
    headers = {"authorization": f"Bearer {bearer}"} if bearer else {}
    return Request(
        method=method,
        path=path,
        query=query or {},
        form=form or {},
        body=body,
        headers=headers,
    )


def call(state: State, mode: Mode, request: Request) -> Response:
    return handle(mode, request, state)


def names(response: Response) -> set[str]:
    return {name.lower() for name, _ in response.headers}


def value(response: Response, header: str) -> str:
    return next(v for n, v in response.headers if n.lower() == header.lower())


# ---- 登錄表與路由的一致性 -------------------------------------------------


def test_registry_counts_and_handlers() -> None:
    security = [c for c in cases.SECURITY_CASES if not c.platform_blocked]
    assert len(security) == 12
    assert len(cases.CONTRACT_CASES) == 6
    assert len(cases.PLATFORM_BLOCKED_CASES) == 1
    assert {c.handler for c in cases.ALL_CASES} <= HANDLER_KEYS


def test_both_modes_implement_every_route_handler() -> None:
    assert set(SECURE) == HANDLER_KEYS
    assert set(INSECURE) == HANDLER_KEYS


def test_every_case_path_is_a_declared_route() -> None:
    declared = {(route.method, route.template) for route in ROUTES}
    for case in cases.ALL_CASES:
        assert (case.method, case.path) in declared, case.case_id


# ---- 安全案例：弱點版呈現、修補版修正 -------------------------------------


def test_fx01_query_sql_injection() -> None:
    state = new_state()
    broken = req("GET", "/search", query={"q": "apple'"})
    assert call(state, "insecure", broken).status == 500
    assert call(state, "secure", broken).status == 200


def test_fx02_reflected_xss() -> None:
    state = new_state()
    request = req("GET", "/greet", query={"q": "x", "name": "<b>x</b>"})
    assert b"<b>x</b>" in call(state, "insecure", request).body
    assert b"<b>x</b>" not in call(state, "secure", request).body


def test_fx03_login_sql_injection_bypass() -> None:
    state = new_state()
    # 以 -- 註解掉密碼條件，不需要正確密碼即登入（弱點版）。
    inject = req("POST", "/login", form={"username": "admin'--", "password": "wrong"})
    assert call(state, "insecure", inject).status == 200
    assert call(state, "secure", inject).status == 401


def test_fx04_error_message_disclosure() -> None:
    state = new_state()
    broken = req("GET", "/search", query={"q": "apple'"})
    insecure = call(state, "insecure", broken)
    assert insecure.status == 500
    assert b"failed" in insecure.body  # 回應洩漏內部錯誤細節
    assert call(state, "secure", broken).status == 200


def test_fx05_missing_security_headers() -> None:
    state = new_state()
    home = req("GET", "/")
    assert "content-security-policy" not in names(call(state, "insecure", home))
    assert "content-security-policy" in names(call(state, "secure", home))


def test_fx06_cors_wildcard() -> None:
    state = new_state()
    request = req("GET", "/api/users")
    assert "access-control-allow-origin" in names(call(state, "insecure", request))
    assert "access-control-allow-origin" not in names(call(state, "secure", request))


def test_fx07_cookie_flags() -> None:
    state = new_state()
    good = req("POST", "/login", form={"username": "alice", "password": "alice-pw"})
    insecure = value(call(state, "insecure", good), "set-cookie")
    secure = value(call(state, "secure", good), "set-cookie")
    assert "HttpOnly" not in insecure
    assert "HttpOnly" in secure
    assert "Secure" in secure


def test_fx08_open_redirect() -> None:
    state = new_state()
    request = req("GET", "/go", query={"next": "http://lab-canary:8080/"})
    insecure = call(state, "insecure", request)
    assert insecure.status == 302
    assert value(insecure, "location") == "http://lab-canary:8080/"
    assert call(state, "secure", request).status == 400


def test_fx09_sensitive_file_exposure() -> None:
    state = new_state()
    request = req("GET", "/backup.sql")
    insecure = call(state, "insecure", request)
    assert insecure.status == 200
    assert b"alice-pw" in insecure.body
    assert call(state, "secure", request).status == 404


def test_fx10_bola() -> None:
    state = new_state()
    others = req("GET", "/api/orders/1002", bearer=ALICE)  # 1002 是 bob 的 order
    assert call(state, "insecure", others).status == 200
    assert call(state, "secure", others).status == 404
    own = req("GET", "/api/orders/1001", bearer=ALICE)  # 1001 是 alice 的 order
    assert call(state, "secure", own).status == 200


def test_fx11_mass_assignment() -> None:
    body = b'{"username": "mallory", "password": "x", "is_admin": true}'
    expectations: tuple[tuple[Mode, int], ...] = (("insecure", 1), ("secure", 0))
    for mode, expected in expectations:
        state = new_state()
        assert call(state, mode, req("POST", "/api/users", body=body)).status == 201
        rows = state.query("SELECT is_admin FROM users WHERE username = ?", ("mallory",))
        assert rows[0][0] == expected


def test_fx12_excessive_data_exposure() -> None:
    state = new_state()
    insecure = call(state, "insecure", req("GET", "/api/users"))
    assert CANARY_BOB.encode() in insecure.body
    assert CANARY_BOB.encode() not in call(state, "secure", req("GET", "/api/users")).body


def test_fx_pb01_path_param_injection_at_app_level() -> None:
    # 不經 guard 直接呼叫：app 層的 path 參數 SQLi 存在（live 才量 guard 的阻擋）。
    state = new_state()
    broken = req("GET", "/users/alice'")
    assert call(state, "insecure", broken).status == 500
    assert call(state, "secure", broken).status == 404


# ---- contract/robustness 案例：弱點版 500、修補版 4xx -----------------------


def test_c1_bad_integer_id() -> None:
    state = new_state()
    request = req("GET", "/api/orders/abc", bearer=ALICE)
    assert call(state, "insecure", request).status == 500
    assert call(state, "secure", request).status == 400


def test_c2_missing_required_field() -> None:
    state = new_state()
    request = req("POST", "/api/users", body=b'{"password": "x"}')
    assert call(state, "insecure", request).status == 500
    assert call(state, "secure", request).status == 400


def test_c3_response_schema_mismatch() -> None:
    state = new_state()
    insecure = call(state, "insecure", req("GET", "/api/users/1"))
    secure = call(state, "secure", req("GET", "/api/users/1"))
    assert b"password" in insecure.body  # 多出未宣告欄位
    assert b"password" not in secure.body


def test_c4_type_confusion_array_body() -> None:
    state = new_state()
    request = req("POST", "/api/users", body=b"[]")
    assert call(state, "insecure", request).status == 500
    assert call(state, "secure", request).status == 400


def test_c5_undocumented_method() -> None:
    state = new_state()
    request = req("PUT", "/api/orders/1001", body=b"{}", bearer=ALICE)
    assert call(state, "insecure", request).status == 500
    assert call(state, "secure", request).status == 405


def test_c6_malformed_json_body() -> None:
    state = new_state()
    request = req("POST", "/api/users", body=b"{bad json")
    assert call(state, "insecure", request).status == 500
    assert call(state, "secure", request).status == 400
