"""GET /scan-profiles 的內容（docs/DECISIONS.md §19.10）：現在可以用的 profile 與引擎。

只列可用的引擎；沒有可用引擎的 profile 不列出。definition_sha256 是這個 profile 實際執行的規則定義的
canonical JSON（規則白名單、會改 method 的規則、強度與門檻）的 sha256：報告以它揭露 profile
（CLAUDE.md §8：調整預算或規則要記錄 profile hash）。
"""

import hashlib
import json
from collections.abc import Sequence
from dataclasses import dataclass

from secscan.scanners.domain.instances import EngineStatus
from secscan.scanners.domain.zap.policy import (
    ACTIVE_SCAN_RULES,
    DEFAULT_STRENGTH,
    METHOD_SWITCHING_RULES,
    RULE_THRESHOLD,
)
from secscan.scans.domain.catalog import (
    PROFILE_RULES,
    WEB_SEED_PATH,
    Engine,
    ProfileRule,
    ScanProfile,
)
from secscan.targets.domain import TargetKind


@dataclass(frozen=True, slots=True)
class ProfileEngine:
    engine: Engine
    version: str | None
    image: str | None
    rule_count: int | None
    definition_sha256: str | None
    grant_requirements: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ProfileView:
    profile: ScanProfile
    target_kinds: tuple[TargetKind, ...]
    requires_spec: bool
    engines: tuple[ProfileEngine, ...]


def profile_views(statuses: Sequence[EngineStatus]) -> tuple[ProfileView, ...]:
    usable = [status for status in statuses if status.available]
    views = (_view(profile, rule, usable) for profile, rule in PROFILE_RULES.items())
    return tuple(view for view in views if view.engines)


def _view(profile: ScanProfile, rule: ProfileRule, usable: Sequence[EngineStatus]) -> ProfileView:
    return ProfileView(
        profile=profile,
        target_kinds=tuple(kind for kind in TargetKind if kind in rule.target_kinds),
        requires_spec=rule.requires_spec,
        engines=tuple(_engine(profile, status) for status in usable if profile in status.profiles),
    )


def _engine(profile: ScanProfile, status: EngineStatus) -> ProfileEngine:
    is_zap = status.engine is Engine.ZAP
    return ProfileEngine(
        engine=status.engine,
        version=status.version,
        image=status.image,
        rule_count=len(ACTIVE_SCAN_RULES[profile]) if is_zap else None,
        definition_sha256=_zap_definition(profile) if is_zap else None,
        grant_requirements=_grant_requirements(status.engine, profile),
    )


def _grant_requirements(engine: Engine, profile: ScanProfile) -> tuple[str, ...]:
    if engine is Engine.ZAP and profile is ScanProfile.WEB_ACTIVE_LAB:
        return (f"GET {WEB_SEED_PATH}",)
    return ()


def _zap_definition(profile: ScanProfile) -> str:
    definition = {
        "method_switching_rules": {
            str(rule): method.value for rule, method in METHOD_SWITCHING_RULES.items()
        },
        "rule_threshold": RULE_THRESHOLD,
        "rules": sorted(ACTIVE_SCAN_RULES[profile]),
        "strength": DEFAULT_STRENGTH,
    }
    canonical = json.dumps(definition, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()
