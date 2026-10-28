"""runner 寫給 guard 的 policy（docs/DECISIONS.md §15.3）：schema 1、canonical、嚴格解析。

guard 以 policy 的內容放行流量，所以解析只接受 runner 寫得出來的那一種寫法：key 完全相符、沒有
重複的 key、布林不能當整數、UUID／IP／origin 都是 canonical；範圍以 Scope 重建。
"""

import json
from dataclasses import replace
from typing import Any
from uuid import UUID, uuid4

import pytest
from hypothesis import given
from hypothesis import strategies as st

from secscan.grants.domain.scope import (
    MAX_ALLOWED_IPS,
    MAX_ALLOWED_PATHS,
    MAX_EXCLUDED_PATHS,
    PATH_MAX_LENGTH,
    HttpMethod,
    Scope,
)
from secscan.guard.domain.policy import (
    MAX_POLICY_BYTES,
    POLICY_SCHEMA,
    Policy,
    PolicyError,
    PolicyState,
    compile_policy,
    decode_policy,
    encode_policy,
    policy_file_name,
)
from secscan.targets.domain import parse_ipv4, parse_origin

RUN_ID = UUID("6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b")
SCAN_ID = UUID("0a1b2c3d-4e5f-4a6b-8c7d-8e9f0a1b2c3d")
TOKEN_DIGEST = "ab" * 32


def _scope(
    *,
    origin: str = "http://lab-target:8080",
    ips: tuple[str, ...] = ("10.89.7.20",),
    paths: tuple[str, ...] = ("/api/items/{id}",),
    allow_all_paths: bool = False,
    excluded: tuple[str, ...] = ("/api/admin",),
    methods: tuple[HttpMethod, ...] = (HttpMethod.GET, HttpMethod.POST),
) -> Scope:
    return Scope(
        origins=(parse_origin(origin),),
        ips=tuple(parse_ipv4(ip) for ip in ips),
        paths=paths,
        allow_all_paths=allow_all_paths,
        excluded_paths=excluded,
        methods=methods,
    )


def _policy(**overrides: Any) -> Policy:
    values: dict[str, Any] = {
        "run_id": RUN_ID,
        "scan_id": SCAN_ID,
        "state": PolicyState.ACTIVE,
        "token_sha256": TOKEN_DIGEST,
        "not_after": 1_767_600_000,
        "renew_until": 1_767_598_830,
        "scope": _scope(),
    }
    values.update(overrides)
    return Policy(**values)


def _document(**overrides: Any) -> dict[str, Any]:
    document: dict[str, Any] = json.loads(encode_policy(_policy()))
    document.update(overrides)
    return document


def _raw(document: object) -> bytes:
    return json.dumps(document).encode()


def test_encodes_the_documented_flat_structure() -> None:
    document = json.loads(encode_policy(_policy()))

    assert document == {
        "schema": POLICY_SCHEMA,
        "run_id": str(RUN_ID),
        "scan_id": str(SCAN_ID),
        "state": "active",
        "token_sha256": TOKEN_DIGEST,
        "not_after": 1_767_600_000,
        "renew_until": 1_767_598_830,
        "origin": "http://lab-target:8080",
        "allowed_ips": ["10.89.7.20"],
        "methods": ["GET", "POST"],
        "allow_all_paths": False,
        "paths": ["/api/items/{id}"],
        "excluded_paths": ["/api/admin"],
    }


def test_encoding_is_canonical() -> None:
    """同樣的 policy 永遠是同樣的 bytes：排序的 key、沒有多餘的空白、只有 ASCII。"""
    raw = encode_policy(_policy())

    assert raw == json.dumps(
        json.loads(raw), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def test_round_trip() -> None:
    policy = _policy()

    assert decode_policy(encode_policy(policy), run_id=RUN_ID) == policy


_ORIGINS = st.sampled_from(
    [
        "http://lab-target:8080",
        "http://lab-target",
        "http://vampi-vuln:5000",
        "http://10.89.7.20:3000",
    ]
)
_PATHS = st.sampled_from(["/", "/api", "/api/items/{id}", "/users/v1/{name}/", "/a:b@c"])


@given(
    origin=_ORIGINS,
    extra_ips=st.sets(st.integers(1, 253), max_size=4),
    paths=st.lists(_PATHS, min_size=1, max_size=4, unique=True),
    allow_all_paths=st.booleans(),
    methods=st.lists(st.sampled_from(list(HttpMethod)), min_size=1, unique=True),
    state=st.sampled_from(list(PolicyState)),
    times=st.tuples(st.integers(0, 10**10), st.integers(0, 10**10)),
)
def test_any_valid_policy_survives_a_round_trip(
    origin: str,
    extra_ips: set[int],
    paths: list[str],
    allow_all_paths: bool,
    methods: list[HttpMethod],
    state: PolicyState,
    times: tuple[int, int],
) -> None:
    host_ip = parse_origin(origin).ip
    ips = {f"10.89.7.{last}" for last in extra_ips} | ({str(host_ip)} if host_ip else set())
    scope = _scope(
        origin=origin,
        ips=tuple(sorted(ips)) or ("10.89.7.21",),
        paths=() if allow_all_paths else tuple(paths),
        allow_all_paths=allow_all_paths,
        excluded=(),
        methods=tuple(methods),
    )
    policy = _policy(scope=scope, state=state, not_after=times[0], renew_until=times[1])

    assert decode_policy(encode_policy(policy), run_id=RUN_ID) == policy


def test_the_largest_grant_fits_in_the_size_limit() -> None:
    """grant 的上限（§10.9）全部用滿時，policy 仍在 512 KiB 以內。"""
    long_segment = "a" * (PATH_MAX_LENGTH - 10)
    scope = _scope(
        ips=tuple(f"10.89.7.{last}" for last in range(1, MAX_ALLOWED_IPS + 1)),
        paths=tuple(f"/{index:04d}/{long_segment}"[:PATH_MAX_LENGTH] for index in range(256)),
        excluded=tuple(
            f"/x{index:04d}/{long_segment}"[:PATH_MAX_LENGTH] for index in range(MAX_EXCLUDED_PATHS)
        ),
        methods=tuple(HttpMethod),
    )
    assert len(scope.paths) == MAX_ALLOWED_PATHS

    raw = encode_policy(_policy(scope=scope))

    assert len(raw) < MAX_POLICY_BYTES
    assert decode_policy(raw, run_id=RUN_ID).scope == scope


def test_blocking_and_renewing_return_new_policies() -> None:
    policy = _policy()

    assert policy.blocked() == replace(policy, state=PolicyState.BLOCKED)
    assert policy.renewed(1_767_598_900) == replace(policy, renew_until=1_767_598_900)
    assert policy.state is PolicyState.ACTIVE


def test_file_name_is_the_canonical_run_id() -> None:
    assert policy_file_name(RUN_ID) == f"{RUN_ID}.json"


def test_compiled_policy_has_the_scope_rules() -> None:
    compiled = compile_policy(_policy())

    assert compiled.policy == _policy()
    assert compiled.rules.methods == frozenset({"GET", "POST"})
    assert compiled.origin == parse_origin("http://lab-target:8080")


@pytest.mark.parametrize(
    "overrides",
    [
        {"token_sha256": "AB" * 32},
        {"token_sha256": "ab" * 31},
        {"token_sha256": "zz" * 32},
        {"not_after": -1},
        {"renew_until": 10**12},
        {"not_after": True},
    ],
)
def test_policy_rejects_invalid_fields(overrides: dict[str, Any]) -> None:
    with pytest.raises(PolicyError):
        _policy(**overrides)


def test_policy_must_have_exactly_one_origin() -> None:
    two = Scope(
        origins=(parse_origin("http://lab-target:8080"), parse_origin("http://other:8080")),
        ips=(parse_ipv4("10.89.7.20"),),
        paths=("/",),
        allow_all_paths=False,
        excluded_paths=(),
        methods=(HttpMethod.GET,),
    )

    with pytest.raises(PolicyError, match="origin"):
        _policy(scope=two)


# --- 嚴格解析 ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "document",
    [
        _document(extra=1),
        {key: value for key, value in _document().items() if key != "paths"},
        _document(schema=2),
        _document(schema=True),
        _document(schema="1"),
        _document(not_after=True),
        _document(not_after=1.5),
        _document(renew_until="1767598830"),
        _document(run_id=str(RUN_ID).upper()),
        _document(run_id=f"{{{RUN_ID}}}"),
        _document(run_id=RUN_ID.hex),
        _document(scan_id=SCAN_ID.hex),
        _document(scan_id=None),
        _document(state="ACTIVE"),
        _document(state="revoked"),
        _document(token_sha256="AB" * 32),
        _document(origin="http://lab-target:8080/"),
        _document(origin="http://LAB-target:8080"),
        _document(origin="http://lab-target:80"),
        _document(origin="https://lab-target:8080"),
        _document(origin="http://user@lab-target:8080"),
        _document(allowed_ips=["010.89.7.20"]),
        _document(allowed_ips="10.89.7.20"),
        _document(allowed_ips=[]),
        _document(methods=["get"]),
        _document(methods=["TRACE"]),
        _document(methods=["GET", "GET"]),
        _document(allow_all_paths="false"),
        _document(allow_all_paths=0),
        _document(allow_all_paths=True),  # 同時還有 paths
        _document(paths="/api"),
        _document(paths=["/api/%2e%2e/admin"]),
        _document(paths=[1]),
        _document(excluded_paths=["/api/items/{id}"]),  # 同時列在允許與排除
        _document(origin="http://10.89.7.30:8080"),  # host 是 IP，卻不在 allowed_ips
    ],
)
def test_rejects_anything_the_runner_would_not_write(document: dict[str, Any]) -> None:
    with pytest.raises(PolicyError):
        decode_policy(_raw(document), run_id=RUN_ID)


def test_rejects_duplicate_keys() -> None:
    raw = encode_policy(_policy()).replace(
        b'"state":"active"', b'"state":"blocked","state":"active"'
    )

    with pytest.raises(PolicyError, match="重複"):
        decode_policy(raw, run_id=RUN_ID)


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"[]",
        b"null",
        b"\xff\xfe",
        b'{"schema": NaN}',
        b'{"schema": Infinity}',
        b"{" + b" " * MAX_POLICY_BYTES + b"}",
    ],
)
def test_rejects_malformed_documents(raw: bytes) -> None:
    with pytest.raises(PolicyError):
        decode_policy(raw, run_id=RUN_ID)


def test_run_id_must_match_the_file_name() -> None:
    """policy 檔名就是 run_id：內容的 run_id 不同就不是這個 run 的 policy。"""
    with pytest.raises(PolicyError, match="run_id"):
        decode_policy(encode_policy(_policy()), run_id=uuid4())


def test_errors_do_not_echo_the_document() -> None:
    secretish = "x" * 40 + "SECRET-TOKEN-VALUE"
    with pytest.raises(PolicyError) as caught:
        decode_policy(_raw(_document(token_sha256=secretish)), run_id=RUN_ID)

    assert "SECRET-TOKEN-VALUE" not in str(caught.value)
