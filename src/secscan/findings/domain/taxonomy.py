"""語意規則群組（docs/DECISIONS.md §25.3、§25.14；CLAUDE.md §10）：rule_groups.yaml 的解析與查找。

- 以 specs 的嚴格 YAML 解析（拒絕 anchor、alias、tag 與重複的 key），欄位逐一檢查，格式不符就是
  TaxonomyError。執行期核對檔案的 sha256 等於 RULE_GROUPS_SHA256：被改動就 fail closed。
- 成員是 (engine, rule, variant)，一個群組只有一個引擎。variant 是 None 或等於 rule（ZAP 的 alertRef
  等於 pluginid）時是「沒有 variant」；`*` 只用在技術識別（技術名是動態的，保留在身分中）。對不到
  就是 fallback `engine:rule[:variant]`：單一引擎、unclassified、標 needs_review。
- 跨引擎只經 `corroborated_by`（使用者的簽核，2026-11-04）：群組的語意以錨點引擎的條件為準，另一個
  引擎的成員只有在同一次 scan、同一個 method 與 path 有錨點的觀察時才併入，否則留在它自己的群組。
  有佐證成員的群組必須 reviewed 並寫下 evidence。`related` 只標示相關，不合併（例如 CORS：兩個工具
  偵測的行為不同）。
- kind 與 category 一致：security 是 vulnerability（偵測條件顯示可被利用的行為）或 misconfiguration
  （缺少或設定不當的防護）；informational 是 technology、detection 或 hardening。兩者在人工 triage
  之前都不是已驗證的漏洞。
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

SCHEMA = 2
RULE_GROUPS_PATH = Path(__file__).parents[1] / "taxonomy" / "rule_groups.yaml"
# 凍結守衛：rule_groups.yaml 的 sha256。改檔案時一併更新它與檔案中的 version
# （test_taxonomy.py 核對）。
RULE_GROUPS_SHA256 = "3c1d616dfe066aaab78dbe04895858dd4b61904ae586b231c8bb599877e6aa38"
# fingerprint 的欄位或規則改變時升版（同一個問題的 fingerprint 會改變）。
FINGERPRINT_VERSION = 2
RULE_GROUP_MAX_LENGTH = 160
TITLE_MAX_LENGTH = 512
WILDCARD = "*"
# observation 的 rule_variant 最多 64 個字元：`群組/技術名` 與「標題: 技術名」都不超過欄位的長度。
_VARIANT_MAX_LENGTH = 64
_WILDCARD_TITLE_MAX_LENGTH = TITLE_MAX_LENGTH - _VARIANT_MAX_LENGTH - len(": ")
_TEXT_MAX_LENGTH = 1024
_LIMITS = DocumentLimits(max_bytes=256 * 1024, max_depth=8, max_nodes=20_000)
# 群組 ID 不含 `:` 與 `/`：不會和 fallback 的 `engine:rule`、技術識別的 `id/技術名` 撞名。
_GROUP_ID = re.compile(r"[a-z][a-z0-9-]{1,62}[a-z0-9]")
# 和 observation 的 source_rule、rule_variant 相同的字元（VARCHAR 64）。
_RULE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_VERSION = re.compile(r"[0-9][0-9.]{0,15}")
_API_CATEGORY = re.compile(r"API(?:[1-9]|10):2023")
_MAX_CWE = 9_999_999
_ENGINES = frozenset({Engine.ZAP, Engine.NUCLEI, Engine.SCHEMATHESIS})
_MEMBER_KEYS = frozenset({"engine", "rule", "variant"})
_GROUP_KEYS = frozenset(
    {"id", "title", "kind", "category", "cwe", "granularity", "resource_scoped"}
    | {"owasp_api_2023", "review", "members", "corroborated_by", "related"}
)
_REQUIRED_KEYS = frozenset({"id", "title", "kind", "category", "review", "members"})


class TaxonomyError(ValueError):
    """rule_groups.yaml 不能用。訊息只說明位置與原因。"""


class FindingKind(StrEnum):
    SECURITY = "security"
    CONTRACT = "contract"
    ROBUSTNESS = "robustness"
    INFORMATIONAL = "informational"


class FindingCategory(StrEnum):
    """kind 之下的分類（分類準則見 docs/DECISIONS.md §25.14）。"""

    VULNERABILITY = "vulnerability"
    MISCONFIGURATION = "misconfiguration"
    TECHNOLOGY = "technology"
    DETECTION = "detection"
    HARDENING = "hardening"
    # fallback：沒有經過審查（rule_groups.yaml 不能使用），人工確認之前分開統計。
    UNCLASSIFIED = "unclassified"


KIND_CATEGORIES: Mapping[FindingKind, frozenset[FindingCategory]] = MappingProxyType(
    {
        FindingKind.SECURITY: frozenset(
            {FindingCategory.VULNERABILITY, FindingCategory.MISCONFIGURATION}
        ),
        FindingKind.INFORMATIONAL: frozenset(
            {FindingCategory.TECHNOLOGY, FindingCategory.DETECTION, FindingCategory.HARDENING}
        ),
    }
)


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
    category: FindingCategory
    cwe: int | None
    granularity: Granularity
    resource_scoped: bool
    owasp_api_2023: ApiMapping | None
    review: ReviewStatus
    evidence: str | None
    members: tuple[MemberKey, ...]
    # 其他引擎、同一次 scan 同一個位置有錨點的觀察時才併入的成員（它們各自屬於另一個群組）。
    corroborated_by: tuple[MemberKey, ...] = ()
    related: tuple[str, ...] = ()

    @property
    def engine(self) -> Engine:
        return self.members[0][0]


@dataclass(frozen=True, slots=True)
class Taxonomy:
    version: str
    groups: tuple[RuleGroup, ...]
    index: Mapping[MemberKey, RuleGroup]
    # (engine, rule) → 以技術名為身分的群組（成員的 variant 是 `*`）。
    wildcards: Mapping[tuple[Engine, str], RuleGroup]
    # 佐證成員 → 它可以併入的錨點群組。
    anchors: Mapping[MemberKey, RuleGroup]
    # 群組 id → 相關的群組 id（對稱）。
    related: Mapping[str, frozenset[str]]

    def lookup(self, engine: Engine, rule: str, variant: str | None) -> RuleGroup | None:
        key = member_key(engine, rule, variant)
        group = self.index.get(key)
        if group is None and key[2] is not None:
            return self.wildcards.get((engine, rule))
        return group

    def anchor_for(self, engine: Engine, rule: str, variant: str | None) -> RuleGroup | None:
        return self.anchors.get(member_key(engine, rule, variant))

    def corroborates(self, engine: Engine) -> bool:
        """這個引擎有沒有佐證成員：沒有的話連結時不必查錨點。"""
        return any(member[0] is engine for member in self.anchors)

    @property
    def anchor_members(self) -> Mapping[MemberKey, str]:
        """錨點群組自己的成員 → 群組 id（連結時查同一次 scan 中有沒有錨點的觀察）。"""
        return MappingProxyType(
            {member: group.id for group in set(self.anchors.values()) for member in group.members}
        )


@dataclass(frozen=True, slots=True)
class Classification:
    """一個觀察對應到的群組（或 fallback）與它帶來的屬性。title 是 None 時用觀察的標題。"""

    rule_group: str
    title: str | None
    kind: FindingKind
    category: FindingCategory
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
        return _fallback(engine, rule, variant, tool_cwe=tool_cwe, severity=severity)
    if WILDCARD not in {member[2] for member in group.members}:
        return group_classification(group)
    if variant is None or not _RULE.fullmatch(variant):
        # 技術名不符規則的字元集（parser 只截斷長度）：不放進審查過的群組，走 fallback（安全審查）。
        return _fallback(engine, rule, variant, tool_cwe=tool_cwe, severity=severity)
    return group_classification(group, variant)


def _fallback(
    engine: Engine, rule: str, variant: str | None, *, tool_cwe: int | None, severity: Severity
) -> Classification:
    """對不到群組：kind 暫時依工具的等級；needs_review、unclassified（分開統計，不當成低風險）。"""
    kind = FindingKind.INFORMATIONAL if severity is Severity.INFO else FindingKind.SECURITY
    return Classification(
        rule_group=fallback_group(engine, rule, variant),
        title=None,
        kind=kind,
        category=FindingCategory.UNCLASSIFIED,
        cwe_id=tool_cwe,
        cwe_source=CweSource.TOOL if tool_cwe is not None else None,
        owasp_api_2023=None,
        granularity=Granularity.PARAMETER,
        resource_scoped=False,
        needs_review=True,
        fallback=True,
    )


def group_classification(group: RuleGroup, variant: str | None = None) -> Classification:
    """群組的屬性；技術識別（成員的 variant 是 `*`）以 `id/技術名` 保留技術名在身分中。"""
    return Classification(
        rule_group=group.id if variant is None else f"{group.id}/{variant}",
        title=group.title if variant is None else f"{group.title}: {variant}",
        kind=group.kind,
        category=group.category,
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
    if document["schema"] != SCHEMA or isinstance(document["schema"], bool):
        raise TaxonomyError(f"schema 必須是 {SCHEMA}")
    version = _text(document["version"], "version", pattern=_VERSION)
    raw_groups = document["groups"]
    if not isinstance(raw_groups, list) or not raw_groups:
        raise TaxonomyError("groups 必須是非空的清單")
    groups = tuple(_group(item, index) for index, item in enumerate(raw_groups))
    index, wildcards = _index(groups)
    return Taxonomy(
        version=version,
        groups=groups,
        index=MappingProxyType(index),
        wildcards=MappingProxyType(wildcards),
        anchors=MappingProxyType(_anchors(groups, index)),
        related=MappingProxyType(_related(groups)),
    )


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
        category=_choice(FindingCategory, item["category"], f"{where}.category"),
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
        members=_members(item["members"], f"{where}.members", wildcard=True),
        corroborated_by=_members(
            item.get("corroborated_by", []), f"{where}.corroborated_by", allow_empty=True
        ),
        related=_related_ids(item.get("related", []), where),
    )
    _check_group(group, where)
    return group


def _check_group(group: RuleGroup, where: str) -> None:
    if group.category not in KIND_CATEGORIES.get(group.kind, frozenset()):
        raise TaxonomyError(f"{where}：category 和 kind 不一致")
    if len({engine for engine, _, _ in group.members}) > 1:
        raise TaxonomyError(f"{where}：成員必須是同一個引擎（跨引擎以 corroborated_by 佐證）")
    wildcard = any(member[2] == WILDCARD for member in group.members)
    if wildcard and (group.category is not FindingCategory.TECHNOLOGY or group.corroborated_by):
        raise TaxonomyError(f"{where}：`*` 只用在沒有佐證成員的技術識別群組")
    if wildcard and not all(member[2] == WILDCARD for member in group.members):
        # 技術識別的 rule_group 是「群組/技術名」，精確成員混在裡面會得到不一致的身分。
        raise TaxonomyError(f"{where}：`*` 不能和精確成員放在同一個群組")
    if wildcard and group.related:
        raise TaxonomyError(f"{where}：技術識別群組不能有 related")
    if wildcard and len(group.title) > _WILDCARD_TITLE_MAX_LENGTH:
        # finding 的標題是「群組標題: 技術名」，技術名最多 64 個字元（VARCHAR 512）。
        raise TaxonomyError(
            f"{where}.title 太長：技術識別的標題最多 {_WILDCARD_TITLE_MAX_LENGTH} 個字元"
        )
    if group.corroborated_by:
        if group.review is not ReviewStatus.REVIEWED or not group.evidence:
            raise TaxonomyError(f"{where}：有佐證成員的群組必須 reviewed，並寫下 evidence")
        if any(engine is group.engine for engine, _, _ in group.corroborated_by):
            raise TaxonomyError(f"{where}：佐證成員必須是其他引擎")
    if group.id in group.related:
        raise TaxonomyError(f"{where}：related 不能是自己")


def _review(value: JsonValue, where: str) -> tuple[ReviewStatus, str | None]:
    if not isinstance(value, dict):
        raise TaxonomyError(f"{where}.review 必須是物件")
    _keys(value, frozenset({"status", "evidence"}), f"{where}.review", required={"status"})
    status = _choice(ReviewStatus, value["status"], f"{where}.review.status")
    evidence = value.get("evidence")
    if evidence is None:
        return status, None
    return status, _text(evidence, f"{where}.review.evidence", max_length=_TEXT_MAX_LENGTH)


def _members(
    value: JsonValue, where: str, *, wildcard: bool = False, allow_empty: bool = False
) -> tuple[MemberKey, ...]:
    if not isinstance(value, list) or (not value and not allow_empty):
        raise TaxonomyError(f"{where} 必須是非空的清單")
    members = tuple(
        _member(member, f"{where}[{position}]", wildcard=wildcard)
        for position, member in enumerate(value)
    )
    if len(set(members)) != len(members):
        raise TaxonomyError(f"{where} 有重複的成員")
    return members


def _member(member: JsonValue, at: str, *, wildcard: bool) -> MemberKey:
    if not isinstance(member, dict):
        raise TaxonomyError(f"{at} 必須是物件")
    _keys(member, _MEMBER_KEYS, at, required={"engine", "rule"})
    engine = _choice(Engine, member["engine"], f"{at}.engine")
    if engine not in _ENGINES:
        raise TaxonomyError(f"{at}.engine 不是會產生觀察的引擎")
    rule = _text(member["rule"], f"{at}.rule", pattern=_RULE)
    variant = member.get("variant")
    if variant is None:
        return (engine, rule, None)
    if variant == WILDCARD and wildcard:
        return (engine, rule, WILDCARD)
    variant = _text(variant, f"{at}.variant", pattern=_RULE)
    if variant == rule:
        raise TaxonomyError(f"{at}.variant 和 rule 相同：省略它")
    return (engine, rule, variant)


def _index(
    groups: tuple[RuleGroup, ...],
) -> tuple[dict[MemberKey, RuleGroup], dict[tuple[Engine, str], RuleGroup]]:
    seen_ids: set[str] = set()
    index: dict[MemberKey, RuleGroup] = {}
    wildcards: dict[tuple[Engine, str], RuleGroup] = {}
    for group in groups:
        if group.id in seen_ids:
            raise TaxonomyError(f"群組 {group.id} 重複")
        seen_ids.add(group.id)
        for engine, rule, variant in group.members:
            if variant == WILDCARD:
                if (engine, rule) in wildcards:
                    raise TaxonomyError(f"群組 {group.id} 與 {wildcards[engine, rule].id} 都是萬用")
                wildcards[(engine, rule)] = group
                continue
            if (engine, rule, variant) in index:
                existing = index[(engine, rule, variant)]
                raise TaxonomyError(f"群組 {group.id} 與 {existing.id} 有相同的成員")
            index[(engine, rule, variant)] = group
    return index, wildcards


def _anchors(
    groups: tuple[RuleGroup, ...], index: Mapping[MemberKey, RuleGroup]
) -> dict[MemberKey, RuleGroup]:
    """佐證成員必須是另一個群組的精確成員（單獨命中時留在那裡），而且只能佐證一個群組。

    佐證成員自己的群組不能也是錨點：合併只有一層，不會沿著佐證串到第三個群組。
    """
    anchors: dict[MemberKey, RuleGroup] = {}
    for group in groups:
        for member in group.corroborated_by:
            if member not in index:
                raise TaxonomyError(f"群組 {group.id} 的佐證成員 {member[1]} 不屬於任何群組")
            if index[member].corroborated_by:
                raise TaxonomyError(f"群組 {group.id} 的佐證成員 {member[1]} 所屬的群組也是錨點")
            if member in anchors:
                raise TaxonomyError(f"佐證成員 {member[1]} 同時屬於兩個錨點群組")
            anchors[member] = group
    return anchors


def _related(groups: tuple[RuleGroup, ...]) -> dict[str, frozenset[str]]:
    """related 是對稱的；技術識別群組的 rule_group 帶技術名，不能被 related 指到。"""
    by_id = {group.id: group for group in groups}
    related: dict[str, set[str]] = {}
    for group in groups:
        for other in group.related:
            if other not in by_id:
                raise TaxonomyError(f"群組 {group.id} 的 related {other} 不存在")
            if any(member[2] == WILDCARD for member in by_id[other].members):
                raise TaxonomyError(f"群組 {group.id} 的 related {other} 是技術識別群組")
            related.setdefault(group.id, set()).add(other)
            related.setdefault(other, set()).add(group.id)
    return {group_id: frozenset(others) for group_id, others in related.items()}


def _related_ids(value: JsonValue, where: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise TaxonomyError(f"{where}.related 必須是清單")
    return tuple(
        _text(item, f"{where}.related[{position}]", pattern=_GROUP_ID)
        for position, item in enumerate(value)
    )


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
