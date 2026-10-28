"""逐請求的判斷（docs/DECISIONS.md §15.5 第 2 到 6 步；SEC-02、SEC-05、SEC-08、SEC-09）。

輸入是 mitmproxy 解析之後的值（§15 實測 5 的對照）：absolute-form 的 host 取自 request target，
Host header 保持原樣；method 是轉送時的原始寫法。
"""

from dataclasses import replace
from uuid import UUID

import pytest
from hypothesis import given
from hypothesis import strategies as st

from secscan.grants.domain.scope import HttpMethod, Scope, path_problem
from secscan.guard.domain.policy import (
    CompiledPolicy,
    Policy,
    PolicyState,
    compile_policy,
)
from secscan.guard.domain.requests import (
    DENY_STATUS,
    Reason,
    RequestView,
    canonical_authority,
    request_reason,
    run_state_reason,
)
from secscan.targets.domain import parse_ipv4, parse_origin

NOT_AFTER = 1_767_600_000
RENEW_UNTIL = 1_767_598_830


def _compiled(
    *,
    origin: str = "http://lab-target:8080",
    paths: tuple[str, ...] = ("/api/items/{id}", "/api/items", "/users/v1/{name}"),
    allow_all_paths: bool = False,
    excluded: tuple[str, ...] = ("/api/admin", "/users/v1/{name}/password"),
    methods: tuple[HttpMethod, ...] = (HttpMethod.GET, HttpMethod.POST),
) -> CompiledPolicy:
    host_ip = parse_origin(origin).ip
    scope = Scope(
        origins=(parse_origin(origin),),
        ips=(host_ip if host_ip is not None else parse_ipv4("10.89.7.20"),),
        paths=paths,
        allow_all_paths=allow_all_paths,
        excluded_paths=excluded,
        methods=methods,
    )
    return compile_policy(
        Policy(
            run_id=UUID(int=1),
            scan_id=UUID(int=2),
            state=PolicyState.ACTIVE,
            token_sha256="ab" * 32,
            not_after=NOT_AFTER,
            renew_until=RENEW_UNTIL,
            scope=scope,
        )
    )


POLICY = _compiled()


def _view(
    target: str = "/api/items/7",
    *,
    method: str = "GET",
    scheme: str = "http",
    host: str = "lab-target",
    port: int = 8080,
    headers: tuple[tuple[str, str], ...] = (("Host", "lab-target:8080"),),
) -> RequestView:
    return RequestView(
        method=method, scheme=scheme, host=host, port=port, target=target, headers=headers
    )


def test_allowed_request_passes() -> None:
    assert request_reason(_view(), POLICY) is None
    assert request_reason(_view("/api/items?page=2&sort=name"), POLICY) is None
    assert request_reason(_view(method="POST"), POLICY) is None


def test_deny_status_is_407_only_for_credentials() -> None:
    assert DENY_STATUS[Reason.PROXY_AUTH_REQUIRED] == 407
    assert {
        DENY_STATUS[reason] for reason in Reason if reason is not Reason.PROXY_AUTH_REQUIRED
    } == {403}


# --- run 的狀態 -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("state", "now", "reason"),
    [
        (PolicyState.ACTIVE, RENEW_UNTIL - 1, None),
        (PolicyState.BLOCKED, RENEW_UNTIL - 1, Reason.RUN_BLOCKED),
        (PolicyState.ACTIVE, RENEW_UNTIL, Reason.POLICY_STALE),
        (PolicyState.ACTIVE, NOT_AFTER, Reason.RUN_EXPIRED),
        (PolicyState.ACTIVE, NOT_AFTER - 0.5, Reason.POLICY_STALE),
        (PolicyState.BLOCKED, NOT_AFTER + 10, Reason.RUN_BLOCKED),
    ],
)
def test_run_state(state: PolicyState, now: float, reason: Reason | None) -> None:
    policy = replace(POLICY.policy, state=state)

    assert run_state_reason(policy, now=now) is reason


def test_expiry_comes_before_staleness() -> None:
    policy = replace(POLICY.policy, renew_until=NOT_AFTER + 100)

    assert run_state_reason(policy, now=NOT_AFTER - 1) is None
    assert run_state_reason(policy, now=NOT_AFTER) is Reason.RUN_EXPIRED


# --- 請求的形狀 -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("view", "reason"),
    [
        (_view(headers=(("Host", "lab-target:8080"), ("Upgrade", "websocket"))), "UPGRADE"),
        (_view(headers=(("Host", "lab-target:8080"), ("upgrade", "h2c"))), "UPGRADE"),
        (_view(headers=(("Host", "lab-target:8080"), ("HTTP2-Settings", "AAA"))), "UPGRADE"),
        (
            _view(headers=(("Host", "lab-target:8080"), ("Connection", "keep-alive, Upgrade"))),
            "UPGRADE",
        ),
        (_view(scheme="https"), "SCHEME"),
        (_view(scheme=""), "SCHEME"),
        (_view("/api/items/7#frag"), "AMBIGUOUS"),
        (_view("/api/items/\x01"), "AMBIGUOUS"),
        (_view("/api/items/ 7"), "AMBIGUOUS"),
        (_view("*", method="OPTIONS"), "AMBIGUOUS"),
        (_view(method="G\x00ET"), "AMBIGUOUS"),
        (_view(method=""), "AMBIGUOUS"),
    ],
)
def test_request_shape(view: RequestView, reason: str) -> None:
    expected = {
        "UPGRADE": Reason.UPGRADE_DENIED,
        "SCHEME": Reason.SCHEME_DENIED,
        "AMBIGUOUS": Reason.PATH_AMBIGUOUS,
    }[reason]

    assert request_reason(view, POLICY) is expected


def test_connection_without_upgrade_is_fine() -> None:
    headers = (("Host", "lab-target:8080"), ("Connection", "keep-alive"))

    assert request_reason(_view(headers=headers), POLICY) is None


# --- 改寫目的地的 header ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "X-HTTP-Method-Override",
        "x-http-method",
        "X-Method-Override",
        "X-Original-URL",
        "X-Rewrite-URL",
        "X-Forwarded-Host",
        "X-Host",
        "X-Forwarded-Server",
        "X-Forwarded-Prefix",
        "Forwarded",
    ],
)
def test_headers_that_redirect_the_target_are_denied(name: str) -> None:
    headers = (("Host", "lab-target:8080"), (name, "DELETE"))

    assert request_reason(_view(headers=headers), POLICY) is Reason.OVERRIDE_HEADER


@pytest.mark.parametrize(
    "target",
    [
        "/api/items?_method=DELETE",
        "/api/items?a=1&_METHOD=DELETE",
        "/api/items?a=1;_method=DELETE",
        "/api/items?%5Fmethod=DELETE",
        "/api/items?%255fmethod=DELETE",
        "/api/items?+_method+=DELETE",
        "/api/items?_method",
    ],
)
def test_method_override_in_the_query_is_denied(target: str) -> None:
    assert request_reason(_view(target), POLICY) is Reason.OVERRIDE_HEADER


def test_query_values_mentioning_method_are_fine() -> None:
    assert request_reason(_view("/api/items?q=_method"), POLICY) is None


@pytest.mark.parametrize(
    "name",
    [
        "X_HTTP_Method_Override",
        "x_original_url",
        "X-Original-Method",
        "X-Forwarded-Path",
        "X_Forwarded_Uri",
    ],
)
def test_override_headers_are_matched_with_underscores_too(name: str) -> None:
    """CGI／WSGI 把 `_` 與 `-` 對應到同一個變數（審查發現：底線的寫法原本會放行）。"""
    headers = (("Host", "lab-target:8080"), (name, "DELETE"))

    assert request_reason(_view(headers=headers), POLICY) is Reason.OVERRIDE_HEADER


@pytest.mark.parametrize(
    "value",
    [
        "a\rX-HTTP-Method-Override: DELETE",  # bare CR：部分 parser 當成換行（審查發現）
        "a\r\n Transfer-Encoding: chunked",  # mitmproxy 合併的 obs-fold
        "a\nb",
        "a\x00b",
        "a\x01b",
        "a\x7fb",
    ],
)
def test_control_characters_in_header_values_are_denied(value: str) -> None:
    headers = (("Host", "lab-target:8080"), ("X-Note", value))

    assert request_reason(_view(headers=headers), POLICY) is Reason.HEADER_INVALID


def test_tabs_and_visible_text_in_header_values_are_fine() -> None:
    headers = (("Host", "lab-target:8080"), ("X-Note", "a\tb c"), ("Accept", "*/*"))

    assert request_reason(_view(headers=headers), POLICY) is None


@pytest.mark.parametrize("name", ["X-Note\r", "X Note", "X:Note", ""])
def test_header_names_must_be_tokens(name: str) -> None:
    headers = (("Host", "lab-target:8080"), (name, "v"))

    assert request_reason(_view(headers=headers), POLICY) is Reason.HEADER_INVALID


# --- authority（SEC-02、SEC-05）---------------------------------------------------------------


@pytest.mark.parametrize(
    ("host", "port", "host_header"),
    [
        ("LAB-target", 8080, "LAB-target:8080"),
        ("lab-target.", 8080, "lab-target.:8080"),
        ("lab_target", 8080, "lab_target:8080"),
        ("lab-target", 8081, "lab-target:8081"),
        ("lab-target", 80, "lab-target"),
        ("10.89.7.20", 8080, "10.89.7.20:8080"),
        ("0x0a59071e", 8080, "0x0a59071e:8080"),
        ("::ffff:10.89.7.20", 8080, "[::ffff:10.89.7.20]:8080"),
        ("lab-canary", 8080, "lab-canary:8080"),
    ],
)
def test_other_authorities_are_denied(host: str, port: int, host_header: str) -> None:
    view = _view(host=host, port=port, headers=(("Host", host_header),))

    assert request_reason(view, POLICY) is Reason.ORIGIN_MISMATCH


@pytest.mark.parametrize(
    "headers",
    [
        (("Host", "other:1234"),),  # absolute-form 指向 target，Host 指向別處
        (("Host", "lab-target:08080"),),
        (("Host", "LAB-TARGET:8080"),),
        (("Host", "lab-target"),),
        (("Host", "lab-target:8080"), ("Host", "lab-target:8080")),
        (("Host", "lab-target:8080, evil:8080"),),
        (),  # HTTP/1.0 沒有 Host
    ],
)
def test_host_header_must_be_the_single_canonical_authority(
    headers: tuple[tuple[str, str], ...],
) -> None:
    assert request_reason(_view(headers=headers), POLICY) is Reason.ORIGIN_MISMATCH


def test_port_80_accepts_both_host_forms() -> None:
    policy = _compiled(origin="http://lab-target")

    for host_header in ("lab-target", "lab-target:80"):
        view = _view(port=80, headers=(("Host", host_header),))
        assert request_reason(view, policy) is None
    assert canonical_authority(policy.origin) == "lab-target"
    assert canonical_authority(POLICY.origin) == "lab-target:8080"


def test_ip_origins_are_compared_literally() -> None:
    policy = _compiled(origin="http://10.89.7.20:3000")
    good = _view(host="10.89.7.20", port=3000, headers=(("Host", "10.89.7.20:3000"),))
    padded = _view(host="10.89.7.020", port=3000, headers=(("Host", "10.89.7.020:3000"),))

    assert request_reason(good, policy) is None
    assert request_reason(padded, policy) is Reason.ORIGIN_MISMATCH


# --- path 與 method（SEC-08）-----------------------------------------------------------------


@pytest.mark.parametrize(
    "target",
    [
        "/api/%2e%2e/admin",
        "/api/items/%37",
        "/api/items/7;jsessionid=1",
        "//api/items/7",
        "/api/./items/7",
        "/api/items/../admin",
        "/api\\items",
        "/api/items/{id}",  # 字面的佔位：parse_route 會把它當成任何一段
        "/api/items/{x",
        "/api/items/" + "a" * 600,
        "api/items/7",
    ],
)
def test_ambiguous_paths_are_denied_without_normalising(target: str) -> None:
    assert request_reason(_view(target), POLICY) is Reason.PATH_AMBIGUOUS


@pytest.mark.parametrize(
    ("target", "method", "reason"),
    [
        ("/api/admin", "GET", Reason.PATH_EXCLUDED),
        ("/API/ADMIN", "GET", Reason.PATH_EXCLUDED),  # 排除不分大小寫
        ("/api/admin/", "GET", Reason.PATH_EXCLUDED),  # 排除忽略結尾的斜線
        ("/users/v1/admin/password", "GET", Reason.PATH_EXCLUDED),  # route 層級的排除擋具體請求
        ("/users/v1/admin/password", "POST", Reason.PATH_EXCLUDED),
        ("/api/items/7", "DELETE", Reason.METHOD_NOT_AUTHORIZED),
        ("/api/items/7", "get", Reason.METHOD_NOT_AUTHORIZED),  # 轉送的是原始寫法
        ("/api/items/7", "TRACE", Reason.METHOD_NOT_AUTHORIZED),
        ("/api/items/7", "CONNECT", Reason.METHOD_NOT_AUTHORIZED),
        ("/API/items/7", "GET", Reason.PATH_NOT_AUTHORIZED),  # 允許要大小寫一致
        ("/api/items/7/", "GET", Reason.PATH_NOT_AUTHORIZED),  # 允許要結尾一致
        ("/api/items/7/x", "GET", Reason.PATH_NOT_AUTHORIZED),
        ("/", "GET", Reason.PATH_NOT_AUTHORIZED),
        ("/api", "GET", Reason.PATH_NOT_AUTHORIZED),
    ],
)
def test_scope_rules(target: str, method: str, reason: Reason) -> None:
    assert request_reason(_view(target, method=method), POLICY) is reason


def test_allow_all_paths_still_honours_exclusions() -> None:
    policy = _compiled(allow_all_paths=True, paths=())

    assert request_reason(_view("/anything/at/all"), policy) is None
    assert request_reason(_view("/api/admin"), policy) is Reason.PATH_EXCLUDED


def test_checks_run_in_the_documented_order() -> None:
    """shape → override header → authority → path/method：同時違反時回報最前面的那一個。"""
    everything = _view(
        "/api/admin",
        method="DELETE",
        host="evil",
        headers=(("Host", "evil"), ("Upgrade", "websocket"), ("X-Original-URL", "/x")),
    )

    assert request_reason(everything, POLICY) is Reason.UPGRADE_DENIED
    no_upgrade = replace(everything, headers=everything.headers[:1] + everything.headers[2:])
    assert request_reason(no_upgrade, POLICY) is Reason.OVERRIDE_HEADER
    no_override = replace(no_upgrade, headers=no_upgrade.headers[:1])
    assert request_reason(no_override, POLICY) is Reason.ORIGIN_MISMATCH
    right_origin = replace(no_override, host="lab-target", headers=(("Host", "lab-target:8080"),))
    assert request_reason(right_origin, POLICY) is Reason.PATH_EXCLUDED


# --- 性質：放行時必然在範圍內 ----------------------------------------------------------------

_HOSTS = st.sampled_from(["lab-target", "LAB-target", "lab-target.", "evil", "10.89.7.20"])
_PORTS = st.sampled_from([8080, 80, 8081])
_PATH_CHARS = st.sampled_from(list("/api/items/v1/{}%.;?#=&_method7 \\:"))
_METHODS = st.sampled_from(["GET", "POST", "get", "DELETE", "TRACE", "OPTIONS"])


@given(
    host=_HOSTS,
    port=_PORTS,
    host_header=st.sampled_from(["lab-target:8080", "lab-target", "evil:8080", "LAB-target:8080"]),
    target=st.lists(_PATH_CHARS, max_size=30).map("".join),
    method=_METHODS,
)
def test_a_passing_request_is_always_inside_the_grant(
    host: str, port: int, host_header: str, target: str, method: str
) -> None:
    view = _view(
        "/" + target, method=method, host=host, port=port, headers=(("Host", host_header),)
    )

    if request_reason(view, POLICY) is not None:
        return
    path = view.target.partition("?")[0]
    assert (view.host, view.port) == ("lab-target", 8080)
    assert host_header == "lab-target:8080"
    assert path_problem(path) is None
    assert "{" not in path
    assert "#" not in view.target
    assert POLICY.rules.classify(method=method, path=path) is None
