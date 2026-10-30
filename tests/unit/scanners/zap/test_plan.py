"""ZAP 的 ExecutionPlan 與 AF plan（docs/DECISIONS.md §18.2、§18.4、§18.5、§18.7）。"""

import json
from ipaddress import IPv4Address
from typing import Any
from uuid import uuid4

import pytest
import yaml
from hypothesis import given
from hypothesis import strategies as st

from secscan.grants.domain.scope import HttpMethod, Scope
from secscan.scanners.domain.plan import ExecutionPlan
from secscan.scanners.domain.zap.plan import (
    ANONYMOUS,
    MIN_PLAN_SECONDS,
    RESERVED_SECONDS,
    PlanWindowTooSmallError,
    ToolSpec,
    ZapAuth,
    ZapBudget,
    ZapPlanError,
    plan_seconds,
    plan_zap_run,
    reject_variables,
)
from secscan.scanners.domain.zap.policy import API_RULES, WEB_RULES, ZAP_IMAGE
from secscan.scanners.domain.zap.script import PLAN_FILE, SCAN_SCRIPT, SPEC_FILE
from secscan.scans.domain.catalog import Engine, ScanProfile
from secscan.targets.domain import parse_origin

ORIGIN = parse_origin("http://lab-web:3000")
RUN_ID, SCAN_ID = uuid4(), uuid4()
BUDGET = ZapBudget(
    requests_per_second=2, max_requests=5_000, remaining_seconds=600, valid_for_seconds=86_400
)
SPEC = ToolSpec(document=b'{"openapi":"3.0.3"}', base_path="/api")


def _scope(
    paths: tuple[str, ...] = ("/",),
    *,
    methods: tuple[HttpMethod, ...] = (HttpMethod.GET,),
    allow_all: bool = False,
) -> Scope:
    return Scope(
        origins=(ORIGIN,),
        ips=(IPv4Address("10.89.7.20"),),
        paths=() if allow_all else paths,
        allow_all_paths=allow_all,
        excluded_paths=(),
        methods=methods,
    )


def _plan(
    profile: ScanProfile = ScanProfile.WEB_ACTIVE_LAB,
    *,
    scope: Scope | None = None,
    auth: ZapAuth = ANONYMOUS,
    budget: ZapBudget = BUDGET,
    spec: ToolSpec | None = None,
) -> ExecutionPlan:
    return plan_zap_run(
        run_id=RUN_ID,
        scan_id=SCAN_ID,
        profile=profile,
        origin=ORIGIN,
        scope=scope if scope is not None else _scope(),
        auth=auth,
        budget=budget,
        spec=spec,
    )


def _af(plan: ExecutionPlan) -> dict[str, Any]:
    [content] = [item.content for item in plan.inputs if item.name == PLAN_FILE]
    document = json.loads(content)
    assert isinstance(document, dict)
    return document


def _job(document: dict[str, Any], kind: str) -> dict[str, Any]:
    [job] = [job for job in document["jobs"] if job["type"] == kind]
    assert isinstance(job, dict)
    return job


# --- ExecutionPlan -------------------------------------------------------------------------------


def test_runs_the_pinned_image_through_the_approved_script() -> None:
    plan = _plan()

    assert (plan.run_id, plan.scan_id, plan.engine) == (RUN_ID, SCAN_ID, Engine.ZAP)
    assert plan.image == ZAP_IMAGE
    assert (plan.entrypoint, plan.arguments) == (("/bin/sh", "-c"), (SCAN_SCRIPT,))
    assert "-silent" in SCAN_SCRIPT
    assert "-nostdout" in SCAN_SCRIPT
    assert plan.limits.wall_clock_seconds == BUDGET.remaining_seconds


def test_anonymous_is_explicit_and_carries_no_header() -> None:
    plan = _plan(auth=ANONYMOUS)

    assert plan.environment == (("SECSCAN_TARGET_AUTH", "none"),)
    assert plan.target_auth is False


def test_a_header_profile_names_the_header_and_the_target_host_only() -> None:
    plan = _plan(auth=ZapAuth(header="X-Api-Key"))

    assert plan.environment == (
        ("SECSCAN_TARGET_AUTH", "header"),
        ("ZAP_AUTH_HEADER", "X-Api-Key"),
        ("ZAP_AUTH_HEADER_SITE", "lab-web"),
    )
    assert plan.target_auth is True
    assert all(name != "ZAP_AUTH_HEADER_VALUE" for name, _ in plan.environment)


def test_the_web_profile_has_no_spec_input() -> None:
    assert [item.name for item in _plan().inputs] == [PLAN_FILE]


def test_the_api_profile_hands_over_the_spec() -> None:
    plan = _plan(ScanProfile.API_ACTIVE_LAB, spec=SPEC)

    assert [item.name for item in plan.inputs] == [PLAN_FILE, SPEC_FILE]
    assert plan.inputs[1].content == SPEC.document


def test_the_plan_is_ascii_and_reads_the_same_as_yaml() -> None:
    [content] = [item.content for item in _plan().inputs if item.name == PLAN_FILE]

    assert content.isascii()
    assert yaml.safe_load(content) == json.loads(content)


# --- AF plan -------------------------------------------------------------------------------


def test_the_web_jobs_run_in_order_and_the_report_always_runs() -> None:
    document = _af(_plan())

    assert [job["type"] for job in document["jobs"]] == [
        "passiveScan-config",
        "spider",
        "passiveScan-wait",
        "activeScan",
        "report",
    ]
    report = _job(document, "report")
    assert report["alwaysRun"] is True
    assert report["parameters"] == {
        "template": "traditional-json",
        "reportDir": "/scan/out",
        "reportFile": "zap-report",
    }


def test_the_api_jobs_import_the_spec_bound_to_the_target() -> None:
    document = _af(_plan(ScanProfile.API_ACTIVE_LAB, spec=SPEC))

    assert [job["type"] for job in document["jobs"]] == [
        "passiveScan-config",
        "openapi",
        "passiveScan-wait",
        "activeScan",
        "report",
    ]
    assert _job(document, "openapi")["parameters"] == {
        "apiFile": "/scan/in/openapi.json",
        "targetUrl": "http://lab-web:3000/api",
        "context": "target",
    }


def test_the_context_comes_from_the_grant() -> None:
    document = _af(_plan(scope=_scope(("/", "/shop/{id}"))))

    [context] = document["env"]["contexts"]
    assert context["name"] == "target"
    assert context["urls"] == ["http://lab-web:3000/"]
    assert context["includePaths"] == [
        r"http\:\/\/lab\-web\:3000/(?:\?.*)?",
        r"http\:\/\/lab\-web\:3000/shop/[^/?#]+(?:\?.*)?",
    ]
    assert context["excludePaths"][-1].startswith("(?!")
    assert _job(document, "passiveScan-config")["parameters"] == {"scanOnlyInScope": True}


def test_the_spider_starts_at_the_root_with_one_thread() -> None:
    spider = _job(_af(_plan()), "spider")["parameters"]

    assert spider["context"] == "target"
    assert spider["url"] == "http://lab-web:3000/"
    assert spider["threadCount"] == 1
    assert (spider["parseGit"], spider["parseDsStore"], spider["parseSVNEntries"]) == (
        False,
        False,
        False,
    )


def test_forms_are_posted_only_when_the_grant_allows_post() -> None:
    get_only = _job(_af(_plan()), "spider")["parameters"]
    with_post = _job(_af(_plan(scope=_scope(methods=(HttpMethod.GET, HttpMethod.POST)))), "spider")[
        "parameters"
    ]

    assert get_only["postForm"] is False
    assert with_post["postForm"] is True


def test_robots_and_sitemap_are_read_only_when_in_scope() -> None:
    root_only = _job(_af(_plan()), "spider")["parameters"]
    everything = _job(_af(_plan(scope=_scope(allow_all=True))), "spider")["parameters"]

    assert (root_only["parseRobotsTxt"], root_only["parseSitemapXml"]) == (False, False)
    assert (everything["parseRobotsTxt"], everything["parseSitemapXml"]) == (True, True)


@pytest.mark.parametrize(
    ("profile", "rules", "spec"),
    [
        (ScanProfile.WEB_ACTIVE_LAB, WEB_RULES, None),
        (ScanProfile.API_ACTIVE_LAB, API_RULES, SPEC),
    ],
)
def test_the_active_scan_runs_only_the_allowlisted_rules(
    profile: ScanProfile, rules: tuple[int, ...], spec: ToolSpec | None
) -> None:
    scope = _scope(methods=(HttpMethod.GET, HttpMethod.POST))
    active = _job(_af(_plan(profile, scope=scope, spec=spec)), "activeScan")

    assert active["parameters"]["threadPerHost"] == 1
    assert active["parameters"]["context"] == "target"
    policy = active["policyDefinition"]
    assert policy["defaultThreshold"] == "off"
    assert policy["defaultStrength"] == "low"
    assert [rule["id"] for rule in policy["rules"]] == list(rules)
    assert {rule["threshold"] for rule in policy["rules"]} == {"medium"}


def _rules(profile: ScanProfile, methods: tuple[HttpMethod, ...]) -> set[int]:
    spec = SPEC if profile is ScanProfile.API_ACTIVE_LAB else None
    plan = _plan(profile, scope=_scope(methods=methods), spec=spec)
    policy = _job(_af(plan), "activeScan")["policyDefinition"]
    return {rule["id"] for rule in policy["rules"]}


def test_rules_that_switch_to_a_method_outside_the_grant_stay_off() -> None:
    """審查 L5（ZAP 的原始碼）：20018 與 40048 一律送 POST，40045 也送 POST。grant 不允許 POST 時
    不執行（live 量到 grant 只允許 GET 時仍有 52 個 POST 被 guard 擋下，TOOLS.md §7.5）。
    """
    get_only = _rules(ScanProfile.WEB_ACTIVE_LAB, (HttpMethod.GET, HttpMethod.HEAD))
    with_post = _rules(ScanProfile.WEB_ACTIVE_LAB, (HttpMethod.GET, HttpMethod.POST))

    assert with_post == set(WEB_RULES)
    assert with_post - get_only == {20018, 40045, 40048}
    # api 的白名單沒有會改 method 的規則：只允許 POST 的 grant 也是完整的清單。
    assert _rules(ScanProfile.API_ACTIVE_LAB, (HttpMethod.POST,)) == set(API_RULES)


def test_the_profiles_do_not_share_one_rule_list() -> None:
    assert set(API_RULES) < set(WEB_RULES)
    # 會改 method 的 GET for POST 只在 web（web 一定允許 GET）。
    assert 10058 in WEB_RULES
    assert 10058 not in API_RULES


@pytest.mark.parametrize(
    "rule",
    [
        40043,  # Log4Shell（OAST）
        90023,  # XXE（OUT_OF_BAND）
        90036,  # SSTI Blind（OUT_OF_BAND）
        20015,  # Heartbleed（非 HTTP）
        10047,  # HTTPS Content Available via HTTP
        10106,  # HTTP Only Site
        30001,  # Buffer Overflow
        30002,  # Format String
        40044,  # Billion Laughs
        40026,  # DOM XSS（瀏覽器）
        90034,  # Cloud Metadata（改 Host）
        50000,  # script
        10104,  # User Agent Fuzzer
        40019,  # 時間型的 SQL 注入
        90037,  # 時間型的命令注入
        100043,  # alpha
    ],
)
def test_excluded_rule_categories_stay_off(rule: int) -> None:
    assert rule not in WEB_RULES
    assert rule not in API_RULES


def test_the_plan_parameters_bound_the_run() -> None:
    document = _af(_plan())

    assert document["env"]["parameters"] == {
        "failOnError": True,
        "failOnWarning": False,
        "progressToStdout": True,
        "maxDuration": BUDGET.remaining_seconds - RESERVED_SECONDS,
    }


def test_job_durations_are_whole_minutes_and_never_unlimited() -> None:
    budget = ZapBudget(
        requests_per_second=2,
        max_requests=5_000,
        remaining_seconds=RESERVED_SECONDS + MIN_PLAN_SECONDS,
        valid_for_seconds=86_400,
    )

    document = _af(_plan(budget=budget))

    assert _job(document, "spider")["parameters"]["maxDuration"] == 1
    assert _job(document, "passiveScan-wait")["parameters"]["maxDuration"] == 1
    active = _job(document, "activeScan")["parameters"]
    assert (active["maxScanDurationInMins"], active["maxRuleDurationInMins"]) == (1, 1)


# --- 時間與預算 --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("budget", "expected"),
    [
        (ZapBudget(2, 5_000, 600, 86_400), 600 - RESERVED_SECONDS),
        (ZapBudget(2, 400, 600, 86_400), 200 - RESERVED_SECONDS),
        (ZapBudget(1, 5_000, 600, 300), 300 - RESERVED_SECONDS),
    ],
)
def test_the_window_is_the_tightest_bound(budget: ZapBudget, expected: int) -> None:
    assert plan_seconds(budget) == expected


@pytest.mark.parametrize(
    "budget",
    [
        ZapBudget(2, 5_000, RESERVED_SECONDS + MIN_PLAN_SECONDS - 1, 86_400),
        ZapBudget(2, 2 * (RESERVED_SECONDS + MIN_PLAN_SECONDS) - 2, 1_500, 86_400),
        ZapBudget(2, 5_000, 1_500, 0),
    ],
)
def test_a_window_below_the_minimum_is_refused(budget: ZapBudget) -> None:
    with pytest.raises(PlanWindowTooSmallError):
        _plan(budget=budget)


@given(
    rps=st.integers(1, 2),
    requests=st.integers(1, 5_000),
    seconds=st.integers(1, 1_500),
    valid=st.integers(0, 100_000),
)
def test_the_window_never_exceeds_any_bound(
    rps: int, requests: int, seconds: int, valid: int
) -> None:
    budget = ZapBudget(rps, requests, seconds, valid)
    try:
        window = plan_seconds(budget)
    except PlanWindowTooSmallError:
        return
    assert window >= MIN_PLAN_SECONDS
    assert window + RESERVED_SECONDS <= min(seconds, requests // rps, valid)


# --- profile 與 method --------------------------------------------------------------------------


def test_the_web_profile_needs_get_on_the_root() -> None:
    with pytest.raises(ZapPlanError, match="GET /"):
        _plan(scope=_scope(("/shop",)))
    with pytest.raises(ZapPlanError, match="GET /"):
        _plan(scope=_scope(methods=(HttpMethod.POST,)))


def test_the_web_profile_takes_no_spec_and_the_api_profile_needs_one() -> None:
    with pytest.raises(ZapPlanError):
        _plan(ScanProfile.WEB_ACTIVE_LAB, spec=SPEC)
    with pytest.raises(ZapPlanError):
        _plan(ScanProfile.API_ACTIVE_LAB, spec=None)


def test_an_api_scan_does_not_need_the_root() -> None:
    plan = _plan(ScanProfile.API_ACTIVE_LAB, scope=_scope(("/api/items",)), spec=SPEC)

    assert plan.engine is Engine.ZAP


def test_plan_variables_are_refused_anywhere_in_the_plan() -> None:
    reject_variables({"jobs": [{"parameters": {"url": "http://x/ok"}}]})
    with pytest.raises(ZapPlanError, match="變數"):
        reject_variables({"jobs": [{"parameters": {"url": "http://x/${ZAP_AUTH_HEADER_VALUE}"}}]})
    with pytest.raises(ZapPlanError, match="變數"):
        reject_variables({"env": {"contexts": [{"includePaths": ["a", "${HOME}"]}]}})
