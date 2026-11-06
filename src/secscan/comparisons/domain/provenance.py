"""將已凍結的來源摘要轉為可比較身分；缺失資料不以目前設定補齊。"""

import hashlib
import json
import re
from dataclasses import dataclass

from secscan.scanners.domain.plan import ImageReference

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


@dataclass(frozen=True, slots=True)
class EngineProvenance:
    engine: str | None
    image_ref: str | None
    engine_version: str | None
    parser_version: str | None
    profile_definition_sha256: str | None
    rule_set_sha256: str | None
    components: tuple[tuple[str, str], ...] | None = None


def definition_digest(provenance: EngineProvenance) -> str | None:
    """只有所有版本與規則集都有記錄時才能比較；不能把兩個未知判作相同。"""
    fields = (
        provenance.engine,
        provenance.image_ref,
        provenance.engine_version,
        provenance.parser_version,
        provenance.profile_definition_sha256,
        provenance.rule_set_sha256,
    )
    if any(not isinstance(value, str) or not value.strip() for value in fields):
        return None
    if not _valid_hash(provenance.profile_definition_sha256) or not _valid_hash(
        provenance.rule_set_sha256
    ):
        return None
    if provenance.image_ref is None or provenance.components is None:
        return None
    try:
        ImageReference.parse(provenance.image_ref)
    except ValueError:
        return None
    components = provenance.components
    if len(dict(components)) != len(components) or any(
        not name.strip() or not version.strip() for name, version in components
    ):
        return None
    encoded = json.dumps(
        (*fields, sorted(components)), separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def mapping_identity(identities: tuple[tuple[str, str] | None, ...]) -> tuple[str, str] | None:
    """所有結果引擎都記錄同一 mapping 與 hash 才能作為 scan 的 mapping 身分。"""
    if not identities or any(identity is None for identity in identities):
        return None
    first = identities[0]
    if first is None or not first[0].strip() or not _valid_hash(first[1]):
        return None
    return first if all(identity == first for identity in identities) else None


def _valid_hash(value: str | None) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None
