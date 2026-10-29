"""preflight 的執行與判斷（docs/DECISIONS.md §16.5）。

- plan：busybox 的 /bin/sh -c <固定的 script>；輸入只有 in/request（完整的 URL）；secret 由
  proxy-url 與 auth-header 檔提供，不進 argv 或環境變數。
- 解析：busybox nc 收到的原始 HTTP 回應（status line、header、body；chunked 解碼），有大小上限，
  格式不合就當成沒有回應。
- 判斷：帶認證的請求符合 §12.5 → passed；匿名的也符合 → inconclusive；guard 拒絕 → blocked；
  沒有回應 → not_executed；其他 → failed。
"""

import json
import time
from uuid import UUID

import pytest

from secscan.auth_profiles.domain.preflight import Preflight
from secscan.scanners.domain.preflight import (
    MAX_RESPONSE_BYTES,
    PREFLIGHT_IMAGE,
    PREFLIGHT_MAX_WALL_CLOCK_SECONDS,
    PREFLIGHT_SCRIPT,
    REQUEST_FILE,
    evaluate,
    parse_response,
    plan_preflight_run,
)
from secscan.scans.domain.catalog import Engine
from secscan.scans.domain.preflight import PreflightResult

RUN = UUID(int=1)
SCAN = UUID(int=2)
PREFLIGHT = Preflight("GET", "/me", 200, {"/user/name": "alice"})


def _response(status: int = 200, body: object = None, headers: str = "") -> bytes:
    content = json.dumps(body if body is not None else {"user": {"name": "alice"}}).encode()
    head = f"HTTP/1.1 {status} X\r\nContent-Type: application/json\r\n{headers}\r\n"
    return head.encode() + content


# --- plan -------------------------------------------------------------------------------------


def test_the_plan_runs_the_fixed_script_with_only_the_url_as_input() -> None:
    plan = plan_preflight_run(
        run_id=RUN, scan_id=SCAN, url="http://lab-target:8080/me", max_duration_seconds=900
    )

    assert plan.engine is Engine.PREFLIGHT
    assert plan.image == PREFLIGHT_IMAGE
    assert (plan.entrypoint, plan.arguments) == (("/bin/sh", "-c"), (PREFLIGHT_SCRIPT,))
    assert plan.environment == ()
    assert [(item.name, item.content) for item in plan.inputs] == [
        (REQUEST_FILE, b"http://lab-target:8080/me")
    ]
    assert plan.target_auth is True
    assert plan.limits.wall_clock_seconds == PREFLIGHT_MAX_WALL_CLOCK_SECONDS


def test_the_plan_never_outlives_the_remaining_time() -> None:
    plan = plan_preflight_run(
        run_id=RUN, scan_id=SCAN, url="http://lab-target:8080/me", max_duration_seconds=7
    )

    assert plan.limits.wall_clock_seconds == 7


@pytest.mark.parametrize(
    "url",
    [
        "https://lab-target/me",  # P0 只有 http
        "http://lab-target:8080",  # 沒有 path
        "http://user@lab-target/me",
        "http://lab-target/me?x=1",
        "http://lab-target/a b",
        "http://lab-target/me\r\nX: 1",
    ],
)
def test_only_plain_http_urls_with_a_path_are_planned(url: str) -> None:
    with pytest.raises(ValueError, match="URL"):
        plan_preflight_run(run_id=RUN, scan_id=SCAN, url=url, max_duration_seconds=60)


def test_secrets_are_read_from_files_never_from_arguments() -> None:
    assert "/scan/secret/proxy-url" in PREFLIGHT_SCRIPT
    assert "/scan/secret/auth-header" in PREFLIGHT_SCRIPT
    assert "/scan/in/request" in PREFLIGHT_SCRIPT
    # 對外的指令只有 nc（host、port 不是 secret）；token 經 printf（ash 的內建指令）進管線。
    assert "base64 -w 0" in PREFLIGHT_SCRIPT
    assert "curl" not in PREFLIGHT_SCRIPT
    assert "wget" not in PREFLIGHT_SCRIPT


# --- 解析 -------------------------------------------------------------------------------------


def test_a_response_is_parsed() -> None:
    response = parse_response(_response(headers="X-Other: 1\r\n"))

    assert response is not None
    assert response.status == 200
    assert response.header("content-type") == "application/json"
    assert json.loads(response.body) == {"user": {"name": "alice"}}


def test_chunked_bodies_are_decoded() -> None:
    raw = (
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        b'4\r\n{"a"\r\n6;x=1\r\n: true\r\n1\r\n}\r\n0\r\n\r\n'
    )

    response = parse_response(raw)

    assert response is not None
    assert json.loads(response.body) == {"a": True}


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"garbage",
        b"HTTP/1.1 200 OK\r\nContent-Type: x\r\n",  # 沒有 header 的結尾
        b"HTTP/2 200\r\n\r\n{}",
        b"HTTP/1.1 99 X\r\n\r\n",
        b"HTTP/1.1 20x X\r\n\r\n",
        b"HTTP/1.1 200 OK\r\n folded: x\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nNo-Colon\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nab\r\n0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\n\r\n" + b"x" * MAX_RESPONSE_BYTES,
    ],
)
def test_malformed_responses_are_no_response(raw: bytes) -> None:
    assert parse_response(raw) is None


# --- 判斷 -------------------------------------------------------------------------------------


def _anonymous() -> bytes:
    return _response(401, {"error": "unauthorized"})


def test_a_matching_authenticated_response_passes() -> None:
    assert evaluate(PREFLIGHT, _response(), _anonymous()) is PreflightResult.PASSED


def test_a_mismatch_fails() -> None:
    assert evaluate(PREFLIGHT, _response(body={"user": {"name": "bob"}}), _anonymous()) is (
        PreflightResult.FAILED
    )
    assert evaluate(PREFLIGHT, _response(302), _anonymous()) is PreflightResult.FAILED


def test_html_is_not_json() -> None:
    html = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>login</html>"

    assert evaluate(PREFLIGHT, html, _anonymous()) is PreflightResult.FAILED


def test_an_unprotected_endpoint_proves_nothing() -> None:
    assert evaluate(PREFLIGHT, _response(), _response()) is PreflightResult.INCONCLUSIVE


def test_guard_denials_are_blocked_not_failed() -> None:
    denial = b"HTTP/1.1 403 Forbidden\r\nX-Secscan-Guard: PATH_NOT_AUTHORIZED\r\n\r\nblocked\n"

    assert evaluate(PREFLIGHT, denial, denial) is PreflightResult.BLOCKED


@pytest.mark.parametrize("authenticated", [None, b"", b"garbage"])
def test_no_usable_response_means_not_executed(authenticated: bytes | None) -> None:
    assert evaluate(PREFLIGHT, authenticated, _anonymous()) is PreflightResult.NOT_EXECUTED


@pytest.mark.parametrize(
    "anonymous",
    [
        None,
        b"",
        b"HTTP/1.1 403 Forbidden\r\nX-Secscan-Guard: RATE_LIMITED\r\n\r\nblocked\n",
    ],
)
def test_without_a_control_response_nothing_is_proven(anonymous: bytes | None) -> None:
    """匿名的對照沒有有效的回應，證明不了端點有受保護（審查發現）：不判 passed。"""
    assert evaluate(PREFLIGHT, _response(), anonymous) is PreflightResult.INCONCLUSIVE


@pytest.mark.parametrize(
    "line",
    [
        b"X-A: x" + b" " * 16_000 + b"\xff",
        b"X-A:" + b" " * 4_000 + b"\x01",
        b"X-A: " + b"\t " * 8_000 + b"x\x7f",
    ],
)
def test_hostile_headers_are_rejected_in_linear_time(line: bytes) -> None:
    """靶機控制的回應（審查發現的 ReDoS）：長串空白加一個不合法的字元不能讓解析卡住。"""
    started = time.perf_counter()

    assert parse_response(b"HTTP/1.1 200 OK\r\n" + line + b"\r\n\r\n{}") is None
    assert time.perf_counter() - started < 0.05


def test_header_values_keep_inner_spaces_and_drop_outer_ones() -> None:
    response = parse_response(b"HTTP/1.1 200 OK\r\nX-A: \t a  b \t\r\nX-B:\r\n\r\n{}")

    assert response is not None
    assert (response.header("x-a"), response.header("x-b")) == ("a  b", "")
