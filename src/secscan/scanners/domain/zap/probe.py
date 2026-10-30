"""ZAP 的 capability probe（docs/DECISIONS.md §18.8）：probe 容器的 plan 與輸出的判斷。

probe 以和掃描相同的強化設定啟動鎖定的映像（runner 用同一套 build_container），列出 /zap/plugin
的 add-on，再以一個 JVM 執行最小的 AF plan：定義 web 與 api 的規則白名單（不存在的 ID 會讓 AF 警告、
以 2 退出）並寫出報告（取得 @version）。context 是 .invalid，不送任何請求。
輸出都是不可信的資料：有大小上限、逐行以 regex 解析，不認得的行略過。
"""

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from uuid import UUID

from secscan.core.json_types import JsonObject
from secscan.grants.domain.scope import HttpMethod
from secscan.scanners.domain.plan import ExecutionPlan, InputFile, ResourceLimits
from secscan.scanners.domain.zap.plan import OUT_DIR, ZAP_MEMORY_BYTES, ZAP_NANO_CPUS, ZAP_PIDS
from secscan.scanners.domain.zap.policy import (
    POLICY_NAMES,
    REQUIRED_ADDONS,
    ZAP_IMAGE,
    ZAP_VERSION,
    policy_definition,
)
from secscan.scanners.domain.zap.script import PROBE_PLAN_FILE, PROBE_REPORT_NAME, PROBE_SCRIPT
from secscan.scans.domain.catalog import Engine, ScanProfile

PROBE_WALL_CLOCK_SECONDS = 180
MAX_PROBE_OUTPUT_BYTES = 64 * 1024
# AF 有警告：在 probe 的 plan 中只可能是不認得的規則 ID 或選項（映像和審查的不同）。
_WARNINGS_EXIT = 2
# /zap/plugin 的檔名：<id>-<status>-<version>.zap。
_ADDON_FILE = re.compile(
    r"([A-Za-z][A-Za-z0-9]*)-(?:alpha|beta|release)-([0-9]+(?:\.[0-9]+){0,3})\.zap"
)
_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")


class ProbeIssue(StrEnum):
    # 容器失敗、逾時，或輸出讀不到。
    FAILED = "FAILED"
    # 版本、add-on 或規則和審查過的不同。
    INCOMPATIBLE = "INCOMPATIBLE"


@dataclass(frozen=True, slots=True)
class ProbeResult:
    issue: ProbeIssue | None
    version: str | None = None
    addons: Mapping[str, str] = field(default_factory=dict)


def plan_zap_probe(probe_id: UUID) -> ExecutionPlan:
    document = json.dumps(_probe_plan(), ensure_ascii=True, indent=1).encode()
    return ExecutionPlan(
        run_id=probe_id,
        scan_id=probe_id,
        engine=Engine.ZAP,
        image=ZAP_IMAGE,
        entrypoint=("/bin/sh", "-c"),
        arguments=(PROBE_SCRIPT,),
        environment=(),
        inputs=(InputFile(PROBE_PLAN_FILE, document),),
        target_auth=False,
        limits=ResourceLimits(
            memory_bytes=ZAP_MEMORY_BYTES,
            nano_cpus=ZAP_NANO_CPUS,
            pids=ZAP_PIDS,
            wall_clock_seconds=PROBE_WALL_CLOCK_SECONDS,
        ),
    )


def evaluate_probe(*, exit_code: int, plugins: bytes | None, report: bytes | None) -> ProbeResult:
    if exit_code == _WARNINGS_EXIT:
        return ProbeResult(ProbeIssue.INCOMPATIBLE)
    if exit_code != 0:
        return ProbeResult(ProbeIssue.FAILED)
    version = _report_version(report)
    addons = _addons(plugins)
    if version is None or addons is None:
        return ProbeResult(ProbeIssue.FAILED)
    required = {name: addons.get(name) for name in REQUIRED_ADDONS}
    if version != ZAP_VERSION or required != dict(REQUIRED_ADDONS):
        return ProbeResult(ProbeIssue.INCOMPATIBLE)
    return ProbeResult(None, version=version, addons=dict(REQUIRED_ADDONS))


def _probe_plan() -> JsonObject:
    profiles = (ScanProfile.WEB_ACTIVE_LAB, ScanProfile.API_ACTIVE_LAB)
    return {
        "env": {
            "contexts": [{"name": "probe", "urls": ["http://probe.invalid/"]}],
            "parameters": {"failOnError": True, "failOnWarning": False, "progressToStdout": True},
        },
        "jobs": [
            *[_policy_job(profile) for profile in profiles],
            {
                "type": "report",
                "alwaysRun": True,
                "parameters": {
                    "template": "traditional-json",
                    "reportDir": OUT_DIR,
                    "reportFile": PROBE_REPORT_NAME,
                },
            },
        ],
    }


def _policy_job(profile: ScanProfile) -> JsonObject:
    return {
        "type": "activeScan-policy",
        "parameters": {"name": POLICY_NAMES[profile]},
        "policyDefinition": policy_definition(profile, methods=frozenset(HttpMethod)),
    }


def _report_version(report: bytes | None) -> str | None:
    if report is None or len(report) > MAX_PROBE_OUTPUT_BYTES:
        return None
    try:
        document = json.loads(report.decode("utf-8"))
    # ValueError 包含 JSONDecodeError 與超過位數上限的整數（不可信的資料；審查 L1）。
    except (UnicodeDecodeError, ValueError, RecursionError):
        return None
    version = document.get("@version") if isinstance(document, dict) else None
    if not isinstance(version, str) or _VERSION.fullmatch(version) is None:
        return None
    return version


def _addons(plugins: bytes | None) -> dict[str, str] | None:
    """每個 add-on 的最大版本（ZAP 在同一個 add-on 有多個檔案時載入最大的版本）。"""
    if plugins is None or len(plugins) > MAX_PROBE_OUTPUT_BYTES:
        return None
    try:
        text = plugins.decode("ascii")
    except UnicodeDecodeError:
        return None
    newest: dict[str, tuple[int, ...]] = {}
    for line in text.splitlines():
        match = _ADDON_FILE.fullmatch(line)
        if match is None:
            continue
        name, version = match[1], tuple(int(part) for part in match[2].split("."))
        if name not in newest or version > newest[name]:
            newest[name] = version
    return {name: ".".join(str(part) for part in version) for name, version in newest.items()}
