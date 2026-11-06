"""執行當下的核准規則清單；它不是每條規則已執行完畢的證據。"""

import hashlib
import json
from collections.abc import Collection
from dataclasses import dataclass

from secscan.grants.domain.scope import HttpMethod
from secscan.scanners.domain.nuclei.policy import load_templates
from secscan.scanners.domain.zap.policy import (
    ACTIVE_SCAN_RULES,
    METHOD_SWITCHING_RULES,
    REQUIRED_ADDONS,
)
from secscan.scans.domain.catalog import Engine, ScanProfile


@dataclass(frozen=True, slots=True)
class RuleSet:
    rules: tuple[str, ...]
    sha256: str


def frozen_rule_set(
    engine: Engine, profile: ScanProfile | None, methods: Collection[HttpMethod]
) -> RuleSet | None:
    """以與 plan 相同的 grant method 過濾；未產生 finding 的引擎不記錄規則清單。"""
    if engine is Engine.ZAP:
        if profile is None:
            raise ValueError("ZAP 的規則清單需要 scan profile")
        active = (
            f"active:{rule}"
            for rule in ACTIVE_SCAN_RULES[profile]
            if rule not in METHOD_SWITCHING_RULES or METHOD_SWITCHING_RULES[rule] in methods
        )
        rules = (*active, f"passive-addon:pscanrules:{REQUIRED_ADDONS['pscanrules']}")
    elif engine is Engine.NUCLEI:
        rules = tuple(template.id for template in load_templates())
    else:
        return None
    ordered = tuple(sorted(set(rules)))
    encoded = json.dumps(ordered, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    return RuleSet(ordered, hashlib.sha256(encoded).hexdigest())
