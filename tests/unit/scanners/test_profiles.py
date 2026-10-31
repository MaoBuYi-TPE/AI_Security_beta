"""GET /scan-profiles 的內容（docs/DECISIONS.md §19.10）：只列現在可以用的 profile 與引擎。"""

import hashlib
import json

import pytest

from secscan.scanners.domain.instances import EngineStatus
from secscan.scanners.domain.profiles import profile_views
from secscan.scanners.domain.zap.policy import API_RULES, WEB_RULES
from secscan.scans.domain.catalog import Engine, ScanProfile
from secscan.targets.domain import TargetKind

ZAP_IMAGE = "zaproxy/zap-stable:20261016@sha256:" + "cd" * 32
FAKE_IMAGE = "busybox:1.38.0@sha256:" + "ab" * 32


def _status(engine: Engine, *, available: bool = True) -> EngineStatus:
    return EngineStatus(
        engine=engine,
        integrated=True,
        available=available,
        image=ZAP_IMAGE if engine is Engine.ZAP else FAKE_IMAGE,
        profiles=tuple(ScanProfile),
        unavailable_reason=None if available else "RUNNER_UNAVAILABLE",
        version="2.17.0" if engine is Engine.ZAP else None,
    )


def test_nothing_available_lists_nothing() -> None:
    assert profile_views(()) == ()
    assert profile_views((_status(Engine.ZAP, available=False),)) == ()


def test_a_profile_lists_its_target_kinds_and_whether_it_needs_a_spec() -> None:
    views = {view.profile: view for view in profile_views((_status(Engine.ZAP),))}

    api, web = views[ScanProfile.API_ACTIVE_LAB], views[ScanProfile.WEB_ACTIVE_LAB]
    assert (api.requires_spec, set(api.target_kinds)) == (
        True,
        {TargetKind.API, TargetKind.HYBRID},
    )
    assert (web.requires_spec, set(web.target_kinds)) == (
        False,
        {TargetKind.WEB, TargetKind.HYBRID},
    )


def test_zap_describes_the_rules_of_each_profile() -> None:
    views = {view.profile: view for view in profile_views((_status(Engine.ZAP),))}

    [api] = views[ScanProfile.API_ACTIVE_LAB].engines
    [web] = views[ScanProfile.WEB_ACTIVE_LAB].engines
    assert (api.engine, api.version, api.image) == (Engine.ZAP, "2.17.0", ZAP_IMAGE)
    assert api.rule_count == len(API_RULES)
    assert web.rule_count == len(WEB_RULES)
    assert api.definition_sha256 != web.definition_sha256
    assert len(api.definition_sha256 or "") == 64
    assert api.grant_requirements == ()
    assert web.grant_requirements == ("GET /",)


def test_the_definition_changes_with_the_rules() -> None:
    """規則的清單改了，sha256 就不同（報告揭露 profile 的 hash，CLAUDE.md §8）。"""
    [view, *_] = profile_views((_status(Engine.ZAP),))
    [engine] = view.engines
    canonical = json.dumps(
        {
            "method_switching_rules": {
                "10058": "GET",
                "20018": "POST",
                "40045": "POST",
                "40048": "POST",
            },
            "rule_threshold": "medium",
            "rules": sorted(API_RULES),
            "strength": "low",
        },
        separators=(",", ":"),
        sort_keys=True,
    )

    assert engine.definition_sha256 == hashlib.sha256(canonical.encode()).hexdigest()


def test_an_engine_without_rules_has_no_definition() -> None:
    [view, *_] = profile_views((_status(Engine.FAKE),))
    [engine] = view.engines

    assert engine.engine is Engine.FAKE
    assert (engine.rule_count, engine.definition_sha256) == (None, None)
    assert engine.grant_requirements == ()


@pytest.mark.parametrize("profile", list(ScanProfile))
def test_only_available_engines_are_listed(profile: ScanProfile) -> None:
    statuses = (_status(Engine.ZAP, available=False), _status(Engine.FAKE))

    views = {view.profile: view for view in profile_views(statuses)}

    assert [engine.engine for engine in views[profile].engines] == [Engine.FAKE]
