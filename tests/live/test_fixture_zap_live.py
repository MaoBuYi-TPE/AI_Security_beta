"""T30：真的 ZAP 經平台掃描自製的 fixture app（docs/SECURITY_AND_TESTING.md §5；
make test-live-fixture）。

fixture app 在 live 自己的 lab 網路上、一次一個（lab_support.start_fixture），跑在 guard 映像的
python（stdlib）。弱點版（insecure）是正例、修補版（secure）是負例的對照。strict-1 的 guard 只擋
path 中的百分比編碼，所以：
- query／form／body／header 的弱點（SQLi、XSS、缺 header…）guard 可達，ZAP 可量測。
- path 參數注入（/users/{username}）的編碼探測被 guard 以 PATH_AMBIGUOUS 擋下 → 平台阻擋
  （DECISIONS.md §21.5），以斷言固定這個事實，不計入掃描器漏報。

量測的機制與 T16 相同（plan_hash、和 /scan-profiles 相同的 profile 定義、guard 流量明細、
observed ⊆ forwarded、guard 只看到 target），直接重用 test_lab_zap_live 的量測工具，不另寫一份。
量測印在輸出，SECSCAN_RECORD_DIR 有設定時另外錄製到 recordings/fixture/<情境>/。
"""

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from tests.live.lab_support import Target, start_fixture, stop_target
from tests.live.support import Api, admin_key

# 重用 T16 的量測機制（Measured、_run_scan、_assert_invariants、ACTIVE_RULES、SHA256）。
from tests.live.test_lab_zap_live import (
    ACTIVE_RULES,
    Measured,
    _assert_invariants,
    _run_scan,
)
from tests.live.zap_support import Lab, lab, wait_for_zap

pytestmark = [pytest.mark.live, pytest.mark.enable_socket]

FIXTURE_SPEC = (
    Path(__file__).resolve().parents[1] / "fixtures" / "openapi" / "fixture-app-openapi3.yml"
)
# 規格中的 API path（grant 要涵蓋這些才會 eligible）；/users/{username} 是平台阻擋的 path 注入案例。
API_PATHS = ["/me", "/api/users", "/api/users/{id}", "/api/orders/{id}", "/users/{username}"]
API_METHODS = ["GET", "HEAD", "POST"]
WEB_METHODS = ["GET", "HEAD", "POST"]
# fixture app 的種子 token（store.py）；auth profile 直接用它，不需要登入步驟。
ALICE_TOKEN = "alice-token"
FIXTURE_ME: dict[str, Any] = {
    "method": "GET",
    "path": "/me",
    "expected_status": 200,
    "expected_json": {"/status": "success"},
}
# query 參數的 SQLi（/search?q=）：q=apple' 讓 sqlite 回 500，ZAP 的 40018 命中（與 Juice Shop
# 的 REST 搜尋相同的機制；query 不受 path 的 % 規則影響）。
SQLI_RULE = "40018"


@pytest.fixture(scope="module")
def admin() -> Api:
    return Api(admin_key())


@pytest.fixture(scope="module")
def definitions(admin: Api) -> dict[str, str]:
    wait_for_zap(admin)
    profiles = admin.data("GET", "/scan-profiles")
    return {
        item["profile"]: engine["definition_sha256"]
        for item in profiles
        for engine in item["engines"]
        if engine["engine"] == "zap"
    }


def _api_lab(admin: Api, target: Target) -> tuple[Lab, str]:
    item = lab(
        admin,
        kind="api",
        paths=API_PATHS,
        methods=API_METHODS,
        host=target.host,
        ip=target.ip,
        port=target.port,
    )
    spec = item.operator.data(
        "POST",
        f"/targets/{item.target_id}/api-specs",
        raw=FIXTURE_SPEC.read_bytes(),
        content_type="application/yaml",
    )
    return item, str(spec["id"])


def _web_lab(admin: Api, target: Target) -> Lab:
    return lab(
        admin,
        kind="web",
        paths=None,
        methods=WEB_METHODS,
        host=target.host,
        ip=target.ip,
        port=target.port,
    )


def _bearer(item: Lab) -> str:
    created = item.operator.data(
        "POST",
        f"/targets/{item.target_id}/auth-profiles",
        {
            "name": "fixture-user",
            "role_label": "standard_user",
            "type": "bearer",
            "secret": ALICE_TOKEN,
            "preflight": FIXTURE_ME,
        },
    )
    return str(created["id"])


def _active(measured: Measured) -> list[dict[str, Any]]:
    return [o for o in measured.observations if o["source_rule"] in ACTIVE_RULES]


# --- 弱點版（正例） --------------------------------------------------------------------------


class TestFixtureVulnerable:
    @pytest.fixture(scope="class")
    def vuln(self) -> Iterator[Target]:
        target = start_fixture(vulnerable=True)
        yield target
        stop_target(target)

    def test_web_scan_finds_query_injection(
        self, admin: Api, definitions: dict[str, str], vuln: Target
    ) -> None:
        wait_for_zap(admin)
        item = _web_lab(admin, vuln)

        measured = _run_scan("fixture-vuln-web", item, vuln, "web_active_lab")

        assert measured.engine["status"] in {"succeeded", "timed_out"}, measured.engine
        _assert_invariants(measured, vuln, definitions["web_active_lab"])
        # 正例：query 參數的 SQLi（40018）命中（traditional spider 從首頁連到 /search?q=）。
        sqli = [o for o in measured.observations if o["source_rule"] == SQLI_RULE]
        assert sqli, measured.rules

    def test_api_scan_is_platform_blocked_on_path_injection(
        self, admin: Api, definitions: dict[str, str], vuln: Target
    ) -> None:
        wait_for_zap(admin)
        item, spec_id = _api_lab(admin, vuln)
        profile_id = _bearer(item)

        measured = _run_scan(
            "fixture-vuln-api",
            item,
            vuln,
            "api_active_lab",
            spec_id=spec_id,
            auth_profile_id=profile_id,
        )

        assert measured.engine["status"] in {"succeeded", "timed_out"}, measured.engine
        _assert_invariants(measured, vuln, definitions["api_active_lab"])
        # 平台阻擋：/users/{username} 的 path 參數注入探測含 %，guard 以 PATH_AMBIGUOUS 擋下，
        # 探測沒有到達靶機（strict-1；DECISIONS §21.5）。
        blocked = {p for p in measured.denied("PATH_AMBIGUOUS") if p.startswith("/users/")}
        assert blocked, sorted(measured.denied("PATH_AMBIGUOUS"))[:5]
        # 可達性：授權的 API GET 有轉送到靶機（BOLA、過度資料暴露等人工案例的前提）。
        assert ("GET", "/api/users") in measured.forwarded()


# --- 修補版（負例；對照組） ------------------------------------------------------------------


class TestFixtureSecure:
    @pytest.fixture(scope="class")
    def secure(self) -> Iterator[Target]:
        target = start_fixture(vulnerable=False)
        yield target
        stop_target(target)

    def test_web_scan_negative_control(
        self, admin: Api, definitions: dict[str, str], secure: Target
    ) -> None:
        wait_for_zap(admin)
        item = _web_lab(admin, secure)

        measured = _run_scan("fixture-secure-web", item, secure, "web_active_lab")

        assert measured.engine["status"] in {"succeeded", "timed_out"}, measured.engine
        _assert_invariants(measured, secure, definitions["web_active_lab"])
        # 負例：修補版沒有任何 active scan 規則的告警。
        assert _active(measured) == [], measured.rules

    def test_api_scan_negative_control(
        self, admin: Api, definitions: dict[str, str], secure: Target
    ) -> None:
        wait_for_zap(admin)
        item, spec_id = _api_lab(admin, secure)
        profile_id = _bearer(item)

        measured = _run_scan(
            "fixture-secure-api",
            item,
            secure,
            "api_active_lab",
            spec_id=spec_id,
            auth_profile_id=profile_id,
        )

        assert measured.engine["status"] in {"succeeded", "timed_out"}, measured.engine
        _assert_invariants(measured, secure, definitions["api_active_lab"])
        assert _active(measured) == [], measured.rules
