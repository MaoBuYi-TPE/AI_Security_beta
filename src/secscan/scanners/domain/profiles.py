"""GET /scan-profiles 的內容（docs/DECISIONS.md §19.10）：現在可以用的 profile 與引擎。

只列可用的引擎；沒有可用引擎的 profile 不列出。definition_sha256 是這個 profile 實際執行的規則定義的
canonical JSON（規則白名單、會改 method 的規則、強度、門檻及覆蓋相關設定）的 sha256；報告以它揭露
profile（CLAUDE.md §8：調整預算或規則要記錄 profile hash）。
"""

import hashlib
import json
from collections.abc import Sequence
from dataclasses import dataclass

from secscan.scanners.domain.instances import EngineStatus
from secscan.scanners.domain.nuclei.policy import (
    INCLUDE_TEMPLATE_IDS,
    NUCLEI_VERSION,
    nuclei_definition_sha256,
)
from secscan.scanners.domain.zap.policy import (
    ACTIVE_SCAN_RULES,
    DEFAULT_STRENGTH,
    INJECT_RULE_HEADER,
    METHOD_SWITCHING_RULES,
    PASSIVE_MAX_ALERTS_PER_RULE,
    PASSIVE_MAX_BODY_BYTES,
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
    if status.engine is Engine.ZAP:
        rule_count: int | None = len(ACTIVE_SCAN_RULES[profile])
        definition: str | None = zap_definition_sha256(profile)
        version = status.version
    elif status.engine is Engine.NUCLEI:
        # 可用性以環境探測（映像存在）判定，不跑容器探測：版本以鎖定的 NUCLEI_VERSION 揭露。
        rule_count = len(INCLUDE_TEMPLATE_IDS)
        definition = nuclei_definition_sha256()
        version = NUCLEI_VERSION
    else:
        rule_count = definition = None
        version = status.version
    return ProfileEngine(
        engine=status.engine,
        version=version,
        image=status.image,
        rule_count=rule_count,
        definition_sha256=definition,
        grant_requirements=_grant_requirements(status.engine, profile),
    )


def _grant_requirements(engine: Engine, profile: ScanProfile) -> tuple[str, ...]:
    if engine is Engine.ZAP and profile is ScanProfile.WEB_ACTIVE_LAB:
        return (f"GET {WEB_SEED_PATH}",)
    if engine is Engine.NUCLEI:
        # nuclei 從 origin 根開始探測（凍結模板多為 GET 偵測；active-probe 需 grant 允許 POST）。
        return (f"GET {WEB_SEED_PATH}",)
    return ()


def zap_definition_sha256(profile: ScanProfile) -> str:
    """runner 在 run 開始時記下（§20.2）：之後改了規則，已執行的 run 仍是當時的定義。"""
    definition = {
        "method_switching_rules": {
            str(rule): method.value for rule, method in METHOD_SWITCHING_RULES.items()
        },
        "inject_rule_header": INJECT_RULE_HEADER,
        "passive_max_alerts_per_rule": PASSIVE_MAX_ALERTS_PER_RULE,
        "passive_max_body_bytes": PASSIVE_MAX_BODY_BYTES,
        "rule_threshold": RULE_THRESHOLD,
        "rules": sorted(ACTIVE_SCAN_RULES[profile]),
        "strength": DEFAULT_STRENGTH,
    }
    canonical = json.dumps(definition, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()
