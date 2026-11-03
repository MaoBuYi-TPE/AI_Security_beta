"""語意規則群組（docs/DECISIONS.md §25.3；CLAUDE.md §10）：taxonomy/rule_groups.yaml 的解析與查找。

- 以 specs 的嚴格 YAML 解析（拒絕 anchor、alias、tag 與重複的 key），欄位逐一檢查，格式不符就是
  TaxonomyError。執行期核對檔案的 sha256 等於 RULE_GROUPS_SHA256：被改動就 fail closed。
- 成員是 (engine, rule, variant)。variant 是 None 或等於 rule（ZAP 的 alertRef 等於 pluginid）時是
  「沒有 variant」。查找只做精確比對；對不到就是 fallback `engine:rule[:variant]`，永遠單一引擎、
  標 needs_review，不和其他工具合併（「不可信的映射不跨工具合併」）。
- 成員跨引擎的群組必須 reviewed、寫下 evidence；provisional 只能單一引擎，而且標 needs_review。
"""

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from functools import cache
from pathlib import Path
from types import MappingProxyType

from secscan.core.json_types import JsonObject, JsonValue
from secscan.findings.domain.normalization import (
    NORMALIZATION_VERSION,
    Severity,
    normalization_document,
)
from secscan.findings.domain.owasp import OWASP_TOP10_2025_SHA256, load_top10
from secscan.scans.domain.catalog import Engine
from secscan.specs.domain.documents import (
    DocumentLimits,
    InvalidSpecError,
    SpecFormat,
    parse_document,
)

SCHEMA = 1
RULE_GROUPS_PATH = Path(__file__).parents[1] / "taxonomy" / "rule_groups.yaml"
# 凍結守衛：rule_groups.yaml 的 sha256。改檔案時一併更新它與檔案中的 version
# （test_taxonomy.py 核對）。
RULE_GROUPS_SHA256 = "cb91abbfdafa2fb579fb6d1755317dfb7805c7a93ed5fed83d6c6b8c9036461c"
# fingerprint 的欄位或規則改變時升版（同一個問題的 fingerprint 會改變）。
FINGERPRINT_VERSION = 1
RULE_GROUP_MAX_LENGTH = 160
TITLE_MAX_LENGTH = 512
_TEXT_MAX_LENGTH = 1024
_LIMITS = DocumentLimits(max_bytes=256 * 1024, max_depth=8, max_nodes=20_000)
# 群組 ID 不含 `:`：不會和 fallback 的 `engine:rule` 撞名。
_GROUP_ID = re.compile(r"[a-z][a-z0-9-]{1,62}[a-z0-9]")
# 和 observation 的 source_rule、rule_variant 相同的字元（VARCHAR 64）。
_RULE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_VERSION = re.compile(r"[0-9][0-9.]{0,15}")
_API_CATEGORY = re.compile(r"API(?:[1-9]|10):2023")
_MAX_CWE = 9_999_999
_ENGINES = frozenset({Engine.ZAP, Engine.NUCLEI, Engine.SCHEMATHESIS})
_GROUP_KEYS = frozenset(
    {"id", "title", "kind", "cwe", "granularity", "resource_scoped", "owasp_api_2023"}
    | {"review", "members"}
)
_REQUIRED_KEYS = frozenset({"id", "title", "kind", "review", "members"})


class TaxonomyError(ValueError):
    """rule_groups.yaml 不能用。訊息只說明位置與原因。"""


class FindingKind(StrEnum):
    SECURITY = "security"
    CONTRACT = "contract"
    ROBUSTNESS = "robustness"
    INFORMATIONAL = "informational"


class Granularity(StrEnum):
    PARAMETER = "parameter"
    ENDPOINT = "endpoint"


class ReviewStatus(StrEnum):
    REVIEWED = "reviewed"
    PROVISIONAL = "provisional"


class CweSource(StrEnum):
    RULE_GROUP = "rule_group"
    TOOL = "tool"


type MemberKey = tuple[Engine, str, str | None]


@dataclass(frozen=True, slots=True)
class ApiMapping:
    category: str
    rationale: str


@dataclass(frozen=True, slots=True)
class RuleGroup:
    id: str
    title: str
    kind: FindingKind
    cwe: int | None
    granularity: Granularity
    resource_scoped: bool
    owasp_api_2023: ApiMapping | None
    review: ReviewStatus
    evidence: str | None
    members: tuple[MemberKey, ...]

    @property
    def engines(self) -> frozenset[Engine]:
        return frozenset(engine for engine, _, _ in self.members)


@dataclass(frozen=True, slots=True)
class Taxonomy:
    version: str
    groups: tuple[RuleGroup, ...]
    index: Mapping[MemberKey, RuleGroup]

    def lookup(self, engine: Engine, rule: str, variant: str | None) -> RuleGroup | None:
        return self.index.get(member_key(engine, rule, variant))


@dataclass(frozen=True, slots=True)
class Classification:
    """一個觀察對應到的群組（或 fallback）與它帶來的屬性。title 是 None 時用觀察的標題。"""

    rule_group: str
    title: str | None
    kind: FindingKind
    cwe_id: int | None
    cwe_source: CweSource | None
    owasp_api_2023: str | None
    granularity: Granularity
    resource_scoped: bool
    needs_review: bool
    # 對不到群組（engine:rule[:variant]）：只有這時用工具回報的 CWE。審查過的群組沒有填 cwe 就是
    # 沒有，不讓工具的值流進官方的 OWASP 對應（code review 發現）。
    fallback: bool = False


def member_key(engine: Engine, rule: str, variant: str | None) -> MemberKey:
    return (engine, rule, None if variant in (None, rule) else variant)


def fallback_group(engine: Engine, rule: str, variant: str | None) -> str:
    _, _, shown = member_key(engine, rule, variant)
    return f"{engine.value}:{rule}" if shown is None else f"{engine.value}:{rule}:{shown}"


def classify(
    taxonomy: Taxonomy,
    engine: Engine,
    rule: str,
    variant: str | None,
    *,
    tool_cwe: int | None,
    severity: Severity,
) -> Classification:
    group = taxonomy.lookup(engine, rule, variant)
    if group is None:
        kind = FindingKind.INFORMATIONAL if severity is Severity.INFO else FindingKind.SECURITY
        return Classification(
            rule_group=fallback_group(engine, rule, variant),
            title=None,
            kind=kind,
            cwe_id=tool_cwe,
            cwe_source=CweSource.TOOL if tool_cwe is not None else None,
            owasp_api_2023=None,
            granularity=Granularity.PARAMETER,
            resource_scoped=False,
            needs_review=True,
            fallback=True,
        )
    return Classification(
        rule_group=group.id,
        title=group.title,
        kind=group.kind,
        cwe_id=group.cwe,
        cwe_source=CweSource.RULE_GROUP if group.cwe is not None else None,
        owasp_api_2023=group.owasp_api_2023.category if group.owasp_api_2023 else None,
        granularity=group.granularity,
        resource_scoped=group.resource_scoped,
        needs_review=group.review is ReviewStatus.PROVISIONAL,
    )


def parse_taxonomy(content: bytes) -> Taxonomy:
    try:
        document = parse_document(content, SpecFormat.YAML, limits=_LIMITS)
    except InvalidSpecError as exc:
        raise TaxonomyError(f"rule_groups.yaml 不是可接受的 YAML：{exc.message}") from None
    _keys(document, frozenset({"schema", "version", "groups"}), "最外層")
    if document["schema"] != SCHEMA:
        raise TaxonomyError(f"schema 必須是 {SCHEMA}")
    version = _text(document["version"], "version", pattern=_VERSION)
    raw_groups = document["groups"]
    if not isinstance(raw_groups, list) or not raw_groups:
        raise TaxonomyError("groups 必須是非空的清單")
    groups = tuple(_group(item, index) for index, item in enumerate(raw_groups))
    return Taxonomy(version, groups, MappingProxyType(_index(groups)))


@cache
def load_taxonomy() -> Taxonomy:
    """已提交的 rule_groups.yaml；sha256 必須等於 RULE_GROUPS_SHA256（被改動就 fail closed）。"""
    content = RULE_GROUPS_PATH.read_bytes()
    if hashlib.sha256(content).hexdigest() != RULE_GROUPS_SHA256:
        raise TaxonomyError("rule_groups.yaml 的 sha256 與 RULE_GROUPS_SHA256 不符")
    return parse_taxonomy(content)


@cache
def mapping_identity() -> tuple[str, str]:
    """(mapping_version, taxonomy_sha256)：rule groups、OWASP 對應表、正規化表與 fingerprint。

    sha256 涵蓋三份資料的內容（改任何一份都會改變）；version 是給人讀的摘要。
    """
    taxonomy = load_taxonomy()
    commit = load_top10().source.commit
    document = {
        "rule_groups_sha256": RULE_GROUPS_SHA256,
        "owasp_top10_2025_sha256": OWASP_TOP10_2025_SHA256,
        "normalization": normalization_document(),
        "fingerprint_version": FINGERPRINT_VERSION,
    }
    encoded = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    version = (
        f"rules-{taxonomy.version}+owasp2025-{commit[:12]}"
        f"+norm-{NORMALIZATION_VERSION}+fp-{FINGERPRINT_VERSION}"
    )
    return version, hashlib.sha256(encoded.encode("ascii")).hexdigest()


def _group(item: JsonValue, index: int) -> RuleGroup:
    where = f"groups[{index}]"
    if not isinstance(item, dict):
        raise TaxonomyError(f"{where} 必須是物件")
    _keys(item, _GROUP_KEYS, where, required=_REQUIRED_KEYS)
    review, evidence = _review(item["review"], where)
    group = RuleGroup(
        id=_text(item["id"], f"{where}.id", pattern=_GROUP_ID),
        title=_text(item["title"], f"{where}.title", max_length=TITLE_MAX_LENGTH),
        kind=_choice(FindingKind, item["kind"], f"{where}.kind"),
        cwe=_cwe(item.get("cwe"), where),
        granularity=_choice(
            Granularity,
            item.get("granularity", Granularity.PARAMETER.value),
            f"{where}.granularity",
        ),
        resource_scoped=_flag(item.get("resource_scoped", False), f"{where}.resource_scoped"),
        owasp_api_2023=_api(item.get("owasp_api_2023"), where),
        review=review,
        evidence=evidence,
        members=_members(item["members"], where),
    )
    if len(group.engines) > 1 and (group.review is not ReviewStatus.REVIEWED or not evidence):
        raise TaxonomyError(f"{where}：跨引擎的群組必須 reviewed，並寫下 evidence")
    return group


def _review(value: JsonValue, where: str) -> tuple[ReviewStatus, str | None]:
    if not isinstance(value, dict):
        raise TaxonomyError(f"{where}.review 必須是物件")
    _keys(value, frozenset({"status", "evidence"}), f"{where}.review", required={"status"})
    status = _choice(ReviewStatus, value["status"], f"{where}.review.status")
    evidence = value.get("evidence")
    if evidence is None:
        return status, None
    return status, _text(evidence, f"{where}.review.evidence", max_length=_TEXT_MAX_LENGTH)


def _members(value: JsonValue, where: str) -> tuple[MemberKey, ...]:
    if not isinstance(value, list) or not value:
        raise TaxonomyError(f"{where}.members 必須是非空的清單")
    members: list[MemberKey] = []
    for position, member in enumerate(value):
        at = f"{where}.members[{position}]"
        if not isinstance(member, dict):
            raise TaxonomyError(f"{at} 必須是物件")
        _keys(member, frozenset({"engine", "rule", "variant"}), at, required={"engine", "rule"})
        engine = _choice(Engine, member["engine"], f"{at}.engine")
        if engine not in _ENGINES:
            raise TaxonomyError(f"{at}.engine 不是會產生觀察的引擎")
        rule = _text(member["rule"], f"{at}.rule", pattern=_RULE)
        variant = member.get("variant")
        if variant is not None:
            variant = _text(variant, f"{at}.variant", pattern=_RULE)
            if variant == rule:
                raise TaxonomyError(f"{at}.variant 和 rule 相同：省略它")
        members.append(member_key(engine, rule, variant))
    if len(set(members)) != len(members):
        raise TaxonomyError(f"{where}.members 有重複的成員")
    return tuple(members)


def _index(groups: tuple[RuleGroup, ...]) -> dict[MemberKey, RuleGroup]:
    seen_ids: set[str] = set()
    index: dict[MemberKey, RuleGroup] = {}
    for group in groups:
        if group.id in seen_ids:
            raise TaxonomyError(f"群組 {group.id} 重複")
        seen_ids.add(group.id)
        for member in group.members:
            if member in index:
                raise TaxonomyError(f"群組 {group.id} 與 {index[member].id} 有相同的成員")
            index[member] = group
    return index


def _api(value: JsonValue, where: str) -> ApiMapping | None:
    if value is None:
        return None
    at = f"{where}.owasp_api_2023"
    if not isinstance(value, dict):
        raise TaxonomyError(f"{at} 必須是物件")
    _keys(value, frozenset({"category", "rationale"}), at, required={"category", "rationale"})
    return ApiMapping(
        _text(value["category"], f"{at}.category", pattern=_API_CATEGORY),
        _text(value["rationale"], f"{at}.rationale", max_length=_TEXT_MAX_LENGTH),
    )


def _cwe(value: JsonValue, where: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not 0 < value <= _MAX_CWE:
        raise TaxonomyError(f"{where}.cwe 必須是正整數")
    return value


def _keys(
    value: JsonObject,
    allowed: frozenset[str],
    where: str,
    *,
    required: frozenset[str] | set[str] | None = None,
) -> None:
    unknown = sorted(set(value) - allowed)
    missing = sorted((allowed if required is None else set(required)) - set(value))
    if unknown or missing:
        raise TaxonomyError(f"{where}：未知的欄位 {unknown}、缺少的欄位 {missing}")


def _text(
    value: JsonValue,
    where: str,
    *,
    pattern: re.Pattern[str] | None = None,
    max_length: int = RULE_GROUP_MAX_LENGTH,
) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > max_length:
        raise TaxonomyError(f"{where} 必須是非空、最多 {max_length} 個字元的字串")
    if pattern is not None and not pattern.fullmatch(value):
        raise TaxonomyError(f"{where} 的格式不符")
    return value


def _flag(value: JsonValue, where: str) -> bool:
    if not isinstance(value, bool):
        raise TaxonomyError(f"{where} 必須是 true 或 false")
    return value


def _choice[E: StrEnum](enum: type[E], value: JsonValue, where: str) -> E:
    if not isinstance(value, str):
        raise TaxonomyError(f"{where} 不是允許的值")
    try:
        return enum(value)
    except ValueError:
        raise TaxonomyError(f"{where} 不是允許的值") from None
