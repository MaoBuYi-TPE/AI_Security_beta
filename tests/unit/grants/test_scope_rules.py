"""grant 的範圍、預算與期限（docs/DECISIONS.md §10.3）。"""

from datetime import UTC, datetime, timedelta, timezone
from ipaddress import IPv4Address, IPv4Network
from uuid import uuid4

import pytest

from secscan.grants.domain.scope import (
    AUTHORIZATION_REFERENCE_MAX_LENGTH,
    MAX_ALLOWED_IPS,
    MAX_ALLOWED_ORIGINS,
    MAX_ALLOWED_PATHS,
    MAX_DURATION_SECONDS,
    MAX_EXCLUDED_PATHS,
    MAX_GRANT_WINDOW,
    MAX_REQUESTS,
    MAX_REQUESTS_PER_SECOND,
    PATH_MAX_LENGTH,
    Budget,
    GrantRequest,
    HttpMethod,
    InvalidScopeError,
    NewScopeGrant,
    Scope,
    ValidityWindow,
    build_new_grant,
    build_scope,
    check_lab,
    resolve_budget,
    resolve_window,
)
from secscan.targets.domain import InvalidOriginError, LabNetwork, OutsideLabError, parse_origin

TARGET = parse_origin("http://vampi-vuln:5000")
NOW = datetime(2026, 10, 19, 12, 0, tzinfo=UTC)
LAB = LabNetwork(IPv4Network("10.89.7.0/24"))


def _scope(**overrides: object) -> Scope:
    params: dict[str, object] = {
        "target_origin": TARGET,
        "origins": ["http://vampi-vuln:5000"],
        "ips": ["10.89.7.20"],
        "paths": ["/users/v1"],
        "allow_all_paths": False,
        "excluded_paths": [],
        "methods": ["GET"],
    }
    params.update(overrides)
    return build_scope(**params)  # type: ignore[arg-type]


# --- 整體 -----------------------------------------------------------------------------------


def test_builds_a_canonical_scope_from_request_values() -> None:
    scope = _scope(
        origins=["HTTP://VAMPI-VULN:5000/", "http://10.89.7.21"],
        ips=["10.89.7.20", "10.89.7.21"],
        paths=["/users/v1", "/books/v1/{book_title}"],
        excluded_paths=["/users/v1/_debug"],
        methods=["GET", "HEAD"],
    )

    assert scope.origins == (TARGET, parse_origin("http://10.89.7.21"))
    assert scope.ips == (IPv4Address("10.89.7.20"), IPv4Address("10.89.7.21"))
    assert scope.paths == ("/users/v1", "/books/v1/{book_title}")
    assert scope.excluded_paths == ("/users/v1/_debug",)
    assert scope.methods == (HttpMethod.GET, HttpMethod.HEAD)
    assert scope.allow_all_paths is False


def test_all_paths_must_be_requested_explicitly() -> None:
    """不用「空清單代表全部」：要全部 path 就明確設定 allow_all_paths。"""
    scope = _scope(paths=[], allow_all_paths=True, excluded_paths=["/logout"])

    assert scope.allow_all_paths is True
    assert scope.paths == ()
    with pytest.raises(InvalidScopeError, match="allowed_paths"):
        _scope(paths=[])
    with pytest.raises(InvalidScopeError, match="allow_all_paths"):
        _scope(paths=["/users/v1"], allow_all_paths=True)


def test_scope_validates_itself_when_built_directly() -> None:
    """從 DB 讀回來的資料也經過同樣的檢查（不合規則就失敗，不會被當成有效範圍）。"""
    with pytest.raises(InvalidScopeError, match="allowed_methods"):
        Scope(
            origins=(TARGET,),
            ips=(IPv4Address("10.89.7.20"),),
            paths=("/x",),
            allow_all_paths=False,
            excluded_paths=(),
            methods=(),
        )
    with pytest.raises(InvalidScopeError, match="allowed_paths"):
        Scope(
            origins=(TARGET,),
            ips=(IPv4Address("10.89.7.20"),),
            paths=("../x",),
            allow_all_paths=False,
            excluded_paths=(),
            methods=(HttpMethod.GET,),
        )


# --- origins --------------------------------------------------------------------------------


def test_origins_must_include_the_target_origin() -> None:
    with pytest.raises(InvalidScopeError, match="target"):
        _scope(origins=["http://juice-shop:3000"])


def test_invalid_origins_are_reported_by_position_without_echoing_them() -> None:
    with pytest.raises(InvalidOriginError, match="allowed_origins 第 2 個") as caught:
        _scope(origins=["http://vampi-vuln:5000", "http://admin:hunter2-secret@lab"])

    assert "hunter2-secret" not in str(caught.value)


def test_origins_must_not_repeat_after_canonicalization() -> None:
    with pytest.raises(InvalidScopeError, match="重複"):
        _scope(origins=["http://vampi-vuln:5000", "HTTP://vampi-vuln:5000/"])


@pytest.mark.parametrize("count", [0, MAX_ALLOWED_ORIGINS + 1])
def test_origin_count_is_bounded(count: int) -> None:
    origins = [f"http://lab-{index}" for index in range(count)]

    with pytest.raises(InvalidScopeError, match="allowed_origins"):
        _scope(origins=origins)


def test_ip_origins_must_be_listed_in_the_allowed_ips() -> None:
    origins = ["http://vampi-vuln:5000", "http://10.89.7.30:8080"]

    with pytest.raises(InvalidScopeError, match="allowed_ips"):
        _scope(origins=origins, ips=["10.89.7.20"])
    assert len(_scope(origins=origins, ips=["10.89.7.20", "10.89.7.30"]).origins) == 2


# --- IPs ------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    ["", "lab", "10.89.7", "010.89.7.20", "10.89.7.20/32", "10.89.7.0/24", "::1", " 10.89.7.20"],
)
def test_ips_must_be_individual_ipv4_addresses(value: str) -> None:
    with pytest.raises(InvalidScopeError, match="allowed_ips 第 1 個"):
        _scope(ips=[value])


def test_ips_must_not_repeat() -> None:
    with pytest.raises(InvalidScopeError, match="重複"):
        _scope(ips=["10.89.7.20", "10.89.7.20"])


@pytest.mark.parametrize("count", [0, MAX_ALLOWED_IPS + 1])
def test_ip_count_is_bounded(count: int) -> None:
    ips = [f"10.89.7.{index + 1}" for index in range(count)]

    with pytest.raises(InvalidScopeError, match="allowed_ips"):
        _scope(ips=ips)


def test_lab_check_covers_every_ip() -> None:
    check_lab(_scope(ips=["10.89.7.20", "10.89.7.21"]), LAB)

    with pytest.raises(OutsideLabError):
        check_lab(_scope(ips=["10.89.7.20", "192.168.1.10"]), LAB)
    with pytest.raises(OutsideLabError):
        check_lab(_scope(ips=["10.89.7.255"]), LAB)


# --- paths ----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "/",
        "/api",
        "/api/",
        "/api/items/{id}",
        "/api/items/{item_id}/tags",
        "/v1.0/a~b_c-d",
        "/a:b@c",
        "/a!$&'()+,=b",
    ],
)
def test_accepts_literal_paths_and_route_placeholders(path: str) -> None:
    assert _scope(paths=[path]).paths == (path,)
    assert _scope(excluded_paths=[path]).excluded_paths == (path,)


@pytest.mark.parametrize(
    "path",
    [
        "",
        "api",
        "//",
        "/api//items",
        "/api/./items",
        "/api/../admin",
        "/.",
        "/..",
        "/api%2Fadmin",
        "/api\\admin",
        "/api?x=1",
        "/api#frag",
        "/api items",
        "/api\titems",
        "/api\x00",
        "/l" + chr(0xE4) + "b",
        "/api/{id",
        "/api/id}",
        "/api/{1id}",
        "/api/x{id}",
        "/api/{id}x",
        "/api/{}",
        "/api;jsessionid=1",
        "/api/*",
        "/api/.*",
        "/" + "a" * PATH_MAX_LENGTH,
    ],
    ids=repr,
)
def test_rejects_ambiguous_paths(path: str) -> None:
    with pytest.raises(InvalidScopeError, match="allowed_paths 第 1 個"):
        _scope(paths=[path])
    with pytest.raises(InvalidScopeError, match="excluded_paths 第 1 個"):
        _scope(excluded_paths=[path])


def test_path_length_limit() -> None:
    longest = "/" + "a" * (PATH_MAX_LENGTH - 1)

    assert _scope(paths=[longest]).paths == (longest,)


def test_paths_must_not_repeat_or_be_both_allowed_and_excluded() -> None:
    with pytest.raises(InvalidScopeError, match=r"allowed_paths.*重複"):
        _scope(paths=["/a", "/a"])
    with pytest.raises(InvalidScopeError, match=r"excluded_paths.*重複"):
        _scope(excluded_paths=["/a", "/a"])
    with pytest.raises(InvalidScopeError, match="同時"):
        _scope(paths=["/a", "/b"], excluded_paths=["/b"])


def test_path_counts_are_bounded() -> None:
    too_many = [f"/p{index}" for index in range(MAX_ALLOWED_PATHS + 1)]
    too_many_excluded = [f"/x{index}" for index in range(MAX_EXCLUDED_PATHS + 1)]

    assert len(_scope(paths=too_many[:-1]).paths) == MAX_ALLOWED_PATHS
    with pytest.raises(InvalidScopeError, match="allowed_paths"):
        _scope(paths=too_many)
    with pytest.raises(InvalidScopeError, match="excluded_paths"):
        _scope(excluded_paths=too_many_excluded)


# --- methods --------------------------------------------------------------------------------


def test_accepts_every_supported_method() -> None:
    methods = ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"]

    assert [method.value for method in _scope(methods=methods).methods] == methods


@pytest.mark.parametrize("method", ["get", "Get", "TRACE", "CONNECT", "PURGE", "", "GET "])
def test_rejects_other_methods(method: str) -> None:
    """method 區分大小寫（RFC 9110）；TRACE、CONNECT 一律不接受。"""
    with pytest.raises(InvalidScopeError, match="allowed_methods 第 1 個"):
        _scope(methods=[method])


def test_methods_must_be_present_and_unique() -> None:
    with pytest.raises(InvalidScopeError, match="allowed_methods"):
        _scope(methods=[])
    with pytest.raises(InvalidScopeError, match="重複"):
        _scope(methods=["GET", "GET"])


# --- 預算 -----------------------------------------------------------------------------------


def test_budget_defaults_to_the_conservative_caps() -> None:
    """M0 到 M2 的保守起始值（ARCHITECTURE.md §3.4）。"""
    assert resolve_budget() == Budget(
        requests_per_second=2, max_requests=5_000, max_duration_seconds=1_500
    )


@pytest.mark.parametrize(
    ("field", "cap"),
    [
        ("requests_per_second", MAX_REQUESTS_PER_SECOND),
        ("max_requests", MAX_REQUESTS),
        ("max_duration_seconds", MAX_DURATION_SECONDS),
    ],
)
def test_requested_budget_is_positive_and_capped(field: str, cap: int) -> None:
    assert getattr(resolve_budget(**{field: 1}), field) == 1
    assert getattr(resolve_budget(**{field: cap}), field) == cap
    for bad in (0, -1, cap + 1, True):
        with pytest.raises(InvalidScopeError, match=field):
            resolve_budget(**{field: bad})


def test_stored_budget_only_needs_positive_integers() -> None:
    """上限是申請當時的政策：M3 調整上限後，既有的 grant 讀回來仍然有效（DECISIONS §10.3）。"""
    assert Budget(requests_per_second=5, max_requests=9_000, max_duration_seconds=3_000)
    for bad in (0, -1, True):
        with pytest.raises(InvalidScopeError, match="max_requests"):
            Budget(requests_per_second=1, max_requests=bad, max_duration_seconds=1)


# --- 期限 -----------------------------------------------------------------------------------


def test_window_starts_now_by_default_and_is_normalized_to_utc() -> None:
    taipei = timezone(timedelta(hours=8))
    until = (NOW + timedelta(days=7)).astimezone(taipei)

    window = resolve_window(None, until, now=NOW)

    assert window == ValidityWindow(valid_from=NOW, valid_until=NOW + timedelta(days=7))
    assert window.valid_until.tzinfo is UTC


def test_window_may_last_at_most_the_maximum() -> None:
    assert resolve_window(NOW, NOW + MAX_GRANT_WINDOW, now=NOW).valid_until == (
        NOW + MAX_GRANT_WINDOW
    )
    with pytest.raises(InvalidScopeError, match="30"):
        resolve_window(NOW, NOW + MAX_GRANT_WINDOW + timedelta(seconds=1), now=NOW)


def test_window_may_start_in_the_past_or_future() -> None:
    assert resolve_window(NOW - timedelta(days=1), NOW + timedelta(days=1), now=NOW)
    assert resolve_window(NOW + timedelta(days=3), NOW + timedelta(days=4), now=NOW)


MINUS_FIVE = timezone(timedelta(hours=-5))
PLUS_FIVE = timezone(timedelta(hours=5))


@pytest.mark.parametrize(
    ("valid_from", "valid_until"),
    [
        (None, datetime(9999, 12, 31, 23, 59, 59, tzinfo=MINUS_FIVE)),
        (datetime(1, 1, 1, tzinfo=PLUS_FIVE), NOW + timedelta(days=1)),
        (datetime(9999, 12, 30, tzinfo=MINUS_FIVE), datetime(9999, 12, 31, 23, tzinfo=MINUS_FIVE)),
    ],
    ids=["until-overflows", "from-underflows", "both-near-the-end-of-time"],
)
def test_extreme_times_are_rejected_instead_of_crashing(
    valid_from: datetime | None, valid_until: datetime
) -> None:
    """換算成 UTC 會超出 datetime 範圍的時間：回 InvalidScopeError（422），不是 OverflowError。"""
    with pytest.raises(InvalidScopeError, match="valid_"):
        resolve_window(valid_from, valid_until, now=NOW)


def test_stored_window_only_needs_aware_and_ordered_times() -> None:
    """已過期的 grant 讀回來仍然是有效的資料；「晚於現在」只在申請時檢查。"""
    past = ValidityWindow(valid_from=NOW - timedelta(days=9), valid_until=NOW - timedelta(days=8))

    assert past.valid_until < NOW
    with pytest.raises(InvalidScopeError, match="valid_"):
        ValidityWindow(valid_from=NOW, valid_until=NOW)
    with pytest.raises(InvalidScopeError, match="valid_"):
        ValidityWindow(valid_from=datetime(2026, 10, 1), valid_until=NOW)


@pytest.mark.parametrize(
    ("valid_from", "valid_until", "reason"),
    [
        (None, NOW, "早於"),  # 從現在開始，到現在結束：期間是空的
        (None, NOW - timedelta(days=1), "早於"),
        (NOW - timedelta(days=2), NOW - timedelta(days=1), "晚於現在"),  # 整段都在過去
        (NOW - timedelta(days=1), NOW, "晚於現在"),
        (NOW + timedelta(days=2), NOW + timedelta(days=1), "早於"),  # 開始晚於結束
        (NOW + timedelta(days=1), NOW + timedelta(days=1), "早於"),
        (None, datetime(2026, 11, 1), "時區"),
        (datetime(2026, 10, 20), NOW + timedelta(days=2), "時區"),
    ],
    ids=[
        "until-now",
        "until-past",
        "window-in-the-past",
        "ends-now",
        "reversed",
        "empty",
        "naive-until",
        "naive-from",
    ],
)
def test_rejects_invalid_windows(
    valid_from: datetime | None, valid_until: datetime, reason: str
) -> None:
    with pytest.raises(InvalidScopeError, match=reason):
        resolve_window(valid_from, valid_until, now=NOW)


# --- 申請 -----------------------------------------------------------------------------------


def _request(**overrides: object) -> GrantRequest:
    fields: dict[str, object] = {
        "origins": ("http://vampi-vuln:5000",),
        "ips": ("10.89.7.20",),
        "paths": ("/users/v1",),
        "allow_all_paths": False,
        "excluded_paths": (),
        "methods": ("GET",),
        "authorization_reference": "LAB-ASSET-001",
        "valid_until": NOW + timedelta(days=7),
    }
    fields.update(overrides)
    return GrantRequest(**fields)  # type: ignore[arg-type]


def test_build_new_grant_applies_every_rule() -> None:
    target_id, requester = uuid4(), uuid4()

    grant = build_new_grant(
        _request(max_requests=100),
        target_id=target_id,
        target_origin=TARGET,
        requested_by=requester,
        now=NOW,
    )

    assert (grant.target_id, grant.requested_by_key_id) == (target_id, requester)
    assert grant.scope == _scope()
    assert grant.budget == resolve_budget(max_requests=100)
    assert grant.window == ValidityWindow(valid_from=NOW, valid_until=NOW + timedelta(days=7))


@pytest.mark.parametrize(
    ("overrides", "error"),
    [
        ({"origins": ("http://juice-shop:3000",)}, InvalidScopeError),
        ({"origins": ("https://vampi-vuln:5000",)}, InvalidOriginError),
        ({"max_requests": MAX_REQUESTS + 1}, InvalidScopeError),
        ({"valid_until": NOW}, InvalidScopeError),
    ],
)
def test_build_new_grant_rejects_any_broken_rule(
    overrides: dict[str, object], error: type[Exception]
) -> None:
    with pytest.raises(error):
        build_new_grant(
            _request(**overrides),
            target_id=uuid4(),
            target_origin=TARGET,
            requested_by=uuid4(),
            now=NOW,
        )


@pytest.mark.parametrize(
    "reference",
    ["", "   ", "\t", "ref\x00", "x" * (AUTHORIZATION_REFERENCE_MAX_LENGTH + 1)],
    ids=repr,
)
def test_new_grant_needs_an_authorization_reference(reference: str) -> None:
    with pytest.raises(ValueError, match="authorization_reference"):
        NewScopeGrant(
            target_id=uuid4(),
            scope=_scope(),
            budget=resolve_budget(),
            window=resolve_window(None, NOW + timedelta(days=1), now=NOW),
            authorization_reference=reference,
            requested_by_key_id=uuid4(),
        )
