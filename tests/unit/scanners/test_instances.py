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

    for engine in (Engine.ZAP, Engine.NUCLEI, Engine.SCHEMATHESIS):
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
    assert (statuses[0].image, statuses[0].profiles) == (None, ())
