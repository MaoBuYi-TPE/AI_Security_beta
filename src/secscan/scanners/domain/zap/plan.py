"""ZAP 的 ExecutionPlan 與 AF plan（docs/DECISIONS.md §18.2、§18.4、§18.5、§18.7）。

- 伺服器產生 AF plan（JSON，也是合法的 YAML 1.1），寫成 in/plan.yaml；ZAP 以 -silent 執行
  （script.py）。
- context 由 grant 的範圍翻譯（scope.py）；web 從 / 開始 spider，api 匯入只含 eligible operation
  的規格（targetUrl 是 target 的 origin 加 base path）。之後 passive、active（只跑白名單的規則）、
  report（alwaysRun：時間到了仍會寫出）。
- maxDuration（秒）取剩下的時間、請求數除以速率、grant 的期限中最小的，再保留 JVM 啟動與報告的
  時間：預算用完之前 ZAP 自己停止。太短就不執行（PlanWindowTooSmallError）。
- 認證：ZapAuth 一定要明確指定（ANONYMOUS 或 header 名稱）；plan 只有模式與 header 名稱，值由
  script 從 0400 的檔案讀出。
- AF 會代換 ${環境變數}：plan 中任何字串含 ${ 都拒絕。
"""

import json
from dataclasses import dataclass
from uuid import UUID

from secscan.core.json_types import JsonObject, JsonValue
from secscan.grants.domain.matching import ScopeRules
from secscan.grants.domain.scope import HttpMethod, Scope
from secscan.scanners.domain.plan import ExecutionPlan, InputFile, ResourceLimits
from secscan.scanners.domain.zap.policy import ZAP_IMAGE, policy_definition
from secscan.scanners.domain.zap.scope import context_paths
from secscan.scanners.domain.zap.script import (
    ANONYMOUS_MODE,
    AUTH_MODE_VARIABLE,
    HEADER_MODE,
    HEADER_VARIABLE,
    PLAN_FILE,
    REPORT_NAME,
    SCAN_SCRIPT,
    SITE_VARIABLE,
    SPEC_FILE,
)
from secscan.scans.domain.catalog import Engine, ScanProfile
from secscan.targets.domain import Origin

# JVM 啟動（離線實測約 15 秒）、報告與收集的保留時間；plan 至少要能跑這麼久。
RESERVED_SECONDS = 60
MIN_PLAN_SECONDS = 60
# 起始值（T16 依量測調整）：記憶體含 tmpfs，JVM 的 heap 在 script 中固定。
ZAP_MEMORY_BYTES = 3 * 1024 * 1024 * 1024
ZAP_NANO_CPUS = 2_000_000_000
ZAP_PIDS = 1024
CONTEXT = "target"
SEED_PATH = "/"
IN_DIR = "/scan/in"
OUT_DIR = "/scan/out"
_ROBOTS = "/robots.txt"
_SITEMAP = "/sitemap.xml"
_VARIABLE = "${"


class ZapPlanError(ValueError):
    """profile、規格與 grant 不相容，或 plan 含有不能交給 AF 的內容。"""


class PlanWindowTooSmallError(ZapPlanError):
    """剩下的時間或請求數不夠 ZAP 執行（runner 以 BUDGET_EXHAUSTED 結束，不送流量）。"""


@dataclass(frozen=True, slots=True)
class ZapAuth:
    """header 是送出目標 secret 的 header 名稱；None 是 anonymous。"""

    header: str | None


ANONYMOUS = ZapAuth(header=None)


@dataclass(frozen=True, slots=True)
class ZapBudget:
    """這個 run 的速率、分到的請求數、剩下的秒數，以及 grant 還有效的秒數。"""

    requests_per_second: int
    max_requests: int
    remaining_seconds: int
    valid_for_seconds: int


@dataclass(frozen=True, slots=True)
class ToolSpec:
    """只含 eligible operation 的規格（specs.domain.tool_document 的輸出）與它的 base path。"""

    document: bytes
    base_path: str


def plan_seconds(budget: ZapBudget) -> int:
    bound = min(
        budget.remaining_seconds,
        budget.max_requests // budget.requests_per_second,
        budget.valid_for_seconds,
    )
    seconds = bound - RESERVED_SECONDS
    if seconds < MIN_PLAN_SECONDS:
        raise PlanWindowTooSmallError("剩下的時間或請求數不夠 ZAP 執行")
    return seconds


def plan_zap_run(
    *,
    run_id: UUID,
    scan_id: UUID,
    profile: ScanProfile,
    origin: Origin,
    scope: Scope,
    auth: ZapAuth,
    budget: ZapBudget,
    spec: ToolSpec | None,
) -> ExecutionPlan:
    document = af_plan(
        profile=profile, origin=origin, scope=scope, seconds=plan_seconds(budget), spec=spec
    )
    inputs = [InputFile(PLAN_FILE, json.dumps(document, ensure_ascii=True, indent=1).encode())]
    if spec is not None:
        inputs.append(InputFile(SPEC_FILE, spec.document))
    return ExecutionPlan(
        run_id=run_id,
        scan_id=scan_id,
        engine=Engine.ZAP,
        image=ZAP_IMAGE,
        entrypoint=("/bin/sh", "-c"),
        arguments=(SCAN_SCRIPT,),
        environment=_environment(auth, origin),
        inputs=tuple(inputs),
        target_auth=auth.header is not None,
        limits=ResourceLimits(
            memory_bytes=ZAP_MEMORY_BYTES,
            nano_cpus=ZAP_NANO_CPUS,
            pids=ZAP_PIDS,
            wall_clock_seconds=budget.remaining_seconds,
        ),
    )


def af_plan(
    *, profile: ScanProfile, origin: Origin, scope: Scope, seconds: int, spec: ToolSpec | None
) -> JsonObject:
    rules = ScopeRules.of(scope)
    minutes = max(1, seconds // 60)
    if profile is ScanProfile.WEB_ACTIVE_LAB:
        discovery = _spider(origin, scope, rules, minutes, spec)
    else:
        discovery = _openapi(origin, spec)
    paths = context_paths(origin, scope)
    document: JsonObject = {
        "env": {
            "contexts": [
                {
                    "name": CONTEXT,
                    "urls": list(paths.urls),
                    "includePaths": list(paths.include),
                    "excludePaths": list(paths.exclude),
                }
            ],
            "parameters": {
                "failOnError": True,
                "failOnWarning": False,
                "progressToStdout": True,
                "maxDuration": seconds,
            },
        },
        "jobs": [
            {"type": "passiveScan-config", "parameters": {"scanOnlyInScope": True}},
            discovery,
            {"type": "passiveScan-wait", "parameters": {"maxDuration": max(1, minutes // 10)}},
            _active_scan(profile, minutes),
            {
                "type": "report",
                "alwaysRun": True,
                "parameters": {
                    "template": "traditional-json",
                    "reportDir": OUT_DIR,
                    "reportFile": REPORT_NAME,
                },
            },
        ],
    }
    reject_variables(document)
    return document


def reject_variables(value: JsonValue) -> None:
    """AF 會把 ${名稱} 代換成環境變數（可能是注入的 secret）：任何字串含 ${ 就拒絕。"""
    if isinstance(value, str):
        if _VARIABLE in value:
            raise ZapPlanError("plan 不可含有 AF 的變數寫法")
    elif isinstance(value, dict):
        for key, child in value.items():
            reject_variables(key)
            reject_variables(child)
    elif isinstance(value, list):
        for child in value:
            reject_variables(child)


def _spider(
    origin: Origin, scope: Scope, rules: ScopeRules, minutes: int, spec: ToolSpec | None
) -> JsonObject:
    if spec is not None:
        raise ZapPlanError("web_active_lab 不接受規格")
    if not _allowed(rules, SEED_PATH):
        raise ZapPlanError("web_active_lab 需要 grant 允許 GET /（spider 的起點）")
    return {
        "type": "spider",
        "parameters": {
            "context": CONTEXT,
            "url": f"{origin}{SEED_PATH}",
            "maxDuration": max(1, minutes // 4),
            "maxDepth": 5,
            "threadCount": 1,
            "postForm": HttpMethod.POST in scope.methods,
            "processForm": True,
            "parseRobotsTxt": _allowed(rules, _ROBOTS),
            "parseSitemapXml": _allowed(rules, _SITEMAP),
            "parseGit": False,
            "parseDsStore": False,
            "parseSVNEntries": False,
        },
    }


def _openapi(origin: Origin, spec: ToolSpec | None) -> JsonObject:
    if spec is None:
        raise ZapPlanError("api_active_lab 需要規格")
    return {
        "type": "openapi",
        "parameters": {
            "apiFile": f"{IN_DIR}/{SPEC_FILE}",
            "targetUrl": f"{origin}{spec.base_path}",
            "context": CONTEXT,
        },
    }


def _active_scan(profile: ScanProfile, minutes: int) -> JsonObject:
    return {
        "type": "activeScan",
        "parameters": {
            "context": CONTEXT,
            "maxRuleDurationInMins": max(1, minutes // 4),
            "maxScanDurationInMins": minutes,
            "threadPerHost": 1,
            "addQueryParam": False,
            "handleAntiCSRFTokens": True,
            "injectPluginIdInHeader": False,
            "scanHeadersAllRequests": False,
        },
        "policyDefinition": policy_definition(profile),
    }


def _allowed(rules: ScopeRules, path: str) -> bool:
    return rules.classify(method=HttpMethod.GET.value, path=path) is None


def _environment(auth: ZapAuth, origin: Origin) -> tuple[tuple[str, str], ...]:
    if auth.header is None:
        return ((AUTH_MODE_VARIABLE, ANONYMOUS_MODE),)
    return (
        (AUTH_MODE_VARIABLE, HEADER_MODE),
        (HEADER_VARIABLE, auth.header),
        (SITE_VARIABLE, origin.host),
    )
