"""ZAP 的 capability probe（docs/DECISIONS.md §18.8）：probe 容器的 plan 與輸出的判斷。

輸出（add-on 的清單、報告）都是不可信的資料：有大小上限、逐行以 regex 解析。
"""

import json
from uuid import uuid4

import pytest

from secscan.scanners.domain.zap.policy import (
    API_RULES,
    REQUIRED_ADDONS,
    WEB_RULES,
    ZAP_IMAGE,
    ZAP_VERSION,
)
from secscan.scanners.domain.zap.probe import (
    MAX_PROBE_OUTPUT_BYTES,
    PROBE_WALL_CLOCK_SECONDS,
    ProbeIssue,
    evaluate_probe,
    plan_zap_probe,
)
from secscan.scanners.domain.zap.script import PROBE_PLAN_FILE, PROBE_SCRIPT
from secscan.scans.domain.catalog import Engine

PLUGINS = "\n".join(
    [
        "Readme.txt",
        "ascanrules-release-78.zap",
        "ascanrules-release-84.zap",
        "automation-beta-0.58.0.zap",
        "automation-beta-0.61.0.zap",
        "commonlib-release-1.44.0.zap",
        "network-beta-0.31.0.zap",
        "openapi-beta-48.zap",
        "openapi-beta-58.zap",
        "pscan-alpha-0.6.0.zap",
        "pscanrules-release-76.zap",
        "reports-release-0.46.0.zap",
        "spider-release-0.20.0.zap",
        "spiderAjax-release-23.33.0.zap",
    ]
).encode()
REPORT = json.dumps({"@programName": "ZAP", "@version": ZAP_VERSION, "site": []}).encode()


def test_the_probe_runs_the_pinned_image_without_secrets() -> None:
    probe_id = uuid4()

    plan = plan_zap_probe(probe_id)

    assert (plan.run_id, plan.scan_id, plan.engine) == (probe_id, probe_id, Engine.ZAP)
    assert plan.image == ZAP_IMAGE
    assert (plan.entrypoint, plan.arguments) == (("/bin/sh", "-c"), (PROBE_SCRIPT,))
    assert plan.environment == ()
    assert plan.target_auth is False
    assert plan.limits.wall_clock_seconds == PROBE_WALL_CLOCK_SECONDS
    assert "-silent" in PROBE_SCRIPT


def test_the_probe_plan_defines_both_policies_and_sends_nothing() -> None:
    [content] = [item.content for item in plan_zap_probe(uuid4()).inputs]
    document = json.loads(content)

    [context] = document["env"]["contexts"]
    assert context["urls"] == ["http://probe.invalid/"]
    jobs = document["jobs"]
    assert [job["type"] for job in jobs] == ["activeScan-policy", "activeScan-policy", "report"]
    rules = [[rule["id"] for rule in job["policyDefinition"]["rules"]] for job in jobs[:2]]
    assert rules == [list(WEB_RULES), list(API_RULES)]
    assert jobs[2]["parameters"]["template"] == "traditional-json"
    assert [item.name for item in plan_zap_probe(uuid4()).inputs] == [PROBE_PLAN_FILE]


def test_a_matching_image_reports_the_version_and_the_required_addons() -> None:
    result = evaluate_probe(exit_code=0, plugins=PLUGINS, report=REPORT)

    assert result.issue is None
    assert result.version == ZAP_VERSION
    assert result.addons == dict(REQUIRED_ADDONS)


def test_the_newest_file_of_an_addon_is_the_one_loaded() -> None:
    older = PLUGINS.replace(b"ascanrules-release-84.zap", b"ascanrules-release-9.zap")

    assert evaluate_probe(exit_code=0, plugins=older, report=REPORT).issue is (
        ProbeIssue.INCOMPATIBLE
    )


@pytest.mark.parametrize("exit_code", [1, 137, 64, 65, -1])
def test_a_failed_container_is_a_probe_failure(exit_code: int) -> None:
    assert evaluate_probe(exit_code=exit_code, plugins=PLUGINS, report=REPORT).issue is (
        ProbeIssue.FAILED
    )


def test_plan_warnings_mean_a_rule_or_an_option_is_missing() -> None:
    # AF 對不存在的規則 ID 警告、以 2 退出（T14 的實測）。
    assert evaluate_probe(exit_code=2, plugins=PLUGINS, report=REPORT).issue is (
        ProbeIssue.INCOMPATIBLE
    )


@pytest.mark.parametrize(
    "report",
    [
        None,
        b"",
        b"not json",
        b"[]",
        json.dumps({"@version": 2170}).encode(),
        json.dumps({"@version": "2.17.0\n"}).encode(),
        b" " * (MAX_PROBE_OUTPUT_BYTES + 1),
        # 超過位數上限的整數是 ValueError，不是 JSONDecodeError（審查 L1）。
        b"1" * 5_000,
        b"[" * 10_000,
    ],
)
def test_an_unreadable_report_is_a_probe_failure(report: bytes | None) -> None:
    assert evaluate_probe(exit_code=0, plugins=PLUGINS, report=report).issue is ProbeIssue.FAILED


def test_another_version_is_incompatible() -> None:
    report = json.dumps({"@version": "2.16.1"}).encode()

    assert evaluate_probe(exit_code=0, plugins=PLUGINS, report=report).issue is (
        ProbeIssue.INCOMPATIBLE
    )


@pytest.mark.parametrize("missing", sorted(REQUIRED_ADDONS))
def test_a_missing_addon_is_incompatible(missing: str) -> None:
    plugins = b"\n".join(
        line for line in PLUGINS.splitlines() if not line.startswith(f"{missing}-".encode())
    )

    assert evaluate_probe(exit_code=0, plugins=plugins, report=REPORT).issue is (
        ProbeIssue.INCOMPATIBLE
    )


@pytest.mark.parametrize("plugins", [None, b"\xff\xfe", b"x" * (MAX_PROBE_OUTPUT_BYTES + 1)])
def test_an_unreadable_plugin_list_is_a_probe_failure(plugins: bytes | None) -> None:
    assert evaluate_probe(exit_code=0, plugins=plugins, report=REPORT).issue is ProbeIssue.FAILED


def test_lines_that_are_not_addon_files_are_ignored() -> None:
    noisy = PLUGINS + b"\n../../etc/passwd\nascanrules-release-84.zap.bak\nautomation--1.zap\n"

    assert evaluate_probe(exit_code=0, plugins=noisy, report=REPORT).issue is None
