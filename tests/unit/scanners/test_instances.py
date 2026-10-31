"""runner 回報的能力（docs/DECISIONS.md §14.7）與 GET /scanners 的引擎狀態。"""

import json

import pytest

from secscan.core.json_types import JsonObject
from secscan.scanners.domain.instances import (
    MAX_CAPABILITIES_BYTES,
    Capabilities,
    CapabilityIssue,
    EngineCapability,
    capabilities_json,
    engine_statuses,
    read_capabilities,
)
from secscan.scans.domain.catalog import Engine, ScanProfile

IMAGE = "busybox:1.38.0@sha256:" + "ab" * 32
READY = Capabilities(engines=(EngineCapability(Engine.FAKE, IMAGE, None),))


@pytest.mark.parametrize(
    "capabilities",
    [
        READY,
        Capabilities(engines=()),
        Capabilities(
            engines=(EngineCapability(Engine.FAKE, IMAGE, CapabilityIssue.IMAGE_MISSING),)
        ),
    ],
)
def test_capabilities_round_trip(capabilities: Capabilities) -> None:
    assert read_capabilities(capabilities_json(capabilities)) == capabilities


def test_the_json_is_small_and_has_no_paths() -> None:
    document = capabilities_json(
        Capabilities(
            engines=tuple(
                EngineCapability(engine, IMAGE, CapabilityIssue.DOCKER_API_UNSUPPORTED)
                for engine in Engine
            )
        )
    )

    assert len(json.dumps(document).encode()) <= MAX_CAPABILITIES_BYTES
    assert document == {
        "engines": {
            engine.value: {"image": IMAGE, "issue": "DOCKER_API_UNSUPPORTED"} for engine in Engine
        }
    }


@pytest.mark.parametrize(
    "document",
    [
        {},
        {"engines": []},
        {"engines": {"burp": {"image": IMAGE, "issue": None}}},
        {"engines": {"fake": "available"}},
        {"engines": {"fake": {"image": 1, "issue": None}}},
        {"engines": {"fake": {"image": IMAGE, "issue": "ON_FIRE"}}},
        # 能寫 DB 的元件不能經由 GET /scanners 把任意文字轉給所有使用者（審查建議）。
        {"engines": {"fake": {"image": "<script>", "issue": None}}},
        {"engines": {"fake": {"image": "busybox:latest", "issue": None}}},
        {"engines": {"fake": {"image": IMAGE + "x" * 4000, "issue": None}}},
    ],
)
def test_unexpected_documents_report_nothing(document: JsonObject) -> None:
    assert read_capabilities(document) == Capabilities(engines=())


def _by_engine(capabilities: Capabilities | None) -> dict[Engine, tuple[bool, str | None]]:
    return {
        status.engine: (status.available, status.unavailable_reason)
        for status in engine_statuses(capabilities)
    }


def test_engines_that_are_not_integrated_say_so() -> None:
    statuses = _by_engine(READY)

    for engine in (Engine.NUCLEI, Engine.SCHEMATHESIS):
        assert statuses[engine] == (False, "NOT_INTEGRATED")
    assert statuses[Engine.FAKE] == (True, None)


def test_without_a_live_runner_nothing_is_available() -> None:
    assert _by_engine(None)[Engine.FAKE] == (False, "RUNNER_UNAVAILABLE")
    assert _by_engine(Capabilities(engines=()))[Engine.FAKE] == (False, "RUNNER_UNAVAILABLE")


def test_a_capability_issue_is_the_reason() -> None:
    broken = Capabilities(
        engines=(EngineCapability(Engine.FAKE, IMAGE, CapabilityIssue.SCAN_NETWORK_NOT_ISOLATED),)
    )

    assert _by_engine(broken)[Engine.FAKE] == (False, "SCAN_NETWORK_NOT_ISOLATED")


def test_statuses_follow_the_engine_order_with_profiles_and_images() -> None:
    statuses = engine_statuses(READY)

    assert [status.engine for status in statuses] == [
        Engine.ZAP,
        Engine.NUCLEI,
        Engine.SCHEMATHESIS,
        Engine.FAKE,
    ]
    fake = statuses[-1]
    assert (fake.integrated, fake.image, fake.profiles) == (True, IMAGE, tuple(ScanProfile))
    assert (statuses[1].image, statuses[1].profiles) == (None, ())


# --- zap 的 probe（docs/DECISIONS.md §18.8）-------------------------------------------------

ZAP_IMAGE = "zaproxy/zap-stable:20261016@sha256:" + "cd" * 32


def test_the_probed_version_round_trips() -> None:
    capabilities = Capabilities(
        engines=(EngineCapability(Engine.ZAP, ZAP_IMAGE, None, version="2.17.0"),)
    )

    document = capabilities_json(capabilities)

    expected = {"image": ZAP_IMAGE, "issue": None, "version": "2.17.0"}
    assert document == {"engines": {"zap": expected}}
    assert read_capabilities(document) == capabilities


@pytest.mark.parametrize("version", ["2.17", "2.17.0-beta", "<b>", 2170, "1.2.3\n"])
def test_a_malformed_version_reports_nothing(version: object) -> None:
    document: JsonObject = {
        "engines": {"zap": {"image": ZAP_IMAGE, "issue": None, "version": version}}  # type: ignore[dict-item]
    }

    assert read_capabilities(document) == Capabilities(engines=())


@pytest.mark.parametrize(
    "issue",
    [
        CapabilityIssue.ENGINE_PROBE_PENDING,
        CapabilityIssue.ENGINE_PROBE_FAILED,
        CapabilityIssue.ENGINE_INCOMPATIBLE,
    ],
)
def test_probe_issues_are_reported_codes(issue: CapabilityIssue) -> None:
    capabilities = Capabilities(engines=(EngineCapability(Engine.ZAP, ZAP_IMAGE, issue),))

    assert read_capabilities(capabilities_json(capabilities)) == capabilities


def _zap(capabilities: Capabilities) -> tuple[object, ...]:
    [zap] = [status for status in engine_statuses(capabilities) if status.engine is Engine.ZAP]
    return (zap.integrated, zap.available, zap.unavailable_reason, zap.version)


def test_zap_is_integrated_and_reports_the_runner_probe() -> None:
    """T15 開放 zap（docs/DECISIONS.md §19.10）：可不可用依 runner 回報的 probe 判斷。"""
    ready = Capabilities(engines=(EngineCapability(Engine.ZAP, ZAP_IMAGE, None, version="2.17.0"),))
    pending = Capabilities(
        engines=(EngineCapability(Engine.ZAP, ZAP_IMAGE, CapabilityIssue.ENGINE_PROBE_PENDING),)
    )

    assert _zap(ready) == (True, True, None, "2.17.0")
    assert _zap(pending) == (True, False, "ENGINE_PROBE_PENDING", None)
    assert _zap(Capabilities(engines=())) == (True, False, "RUNNER_UNAVAILABLE", None)
