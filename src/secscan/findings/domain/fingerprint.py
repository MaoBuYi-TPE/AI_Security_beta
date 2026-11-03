"""保守的 fingerprint（docs/DECISIONS.md §25.6；ARCHITECTURE.md §10；DECISIONS.md §2 第 11 列）。

sha256(canonical JSON)：target、kind、語意規則群組、method、route（含是否為樣板）、參數位置與名稱、
auth role（含身分是否經過驗證）與必要時的 resource。每個欄位都要相同才是同一個 finding；標題、
證據、等級、query、工具的 CWE 都不在裡面（不能只靠相似的文字或 CWE 合併）。
- route：scan 有規格時，把觀察的 (method, path) 以 coverage 的規則對到凍結、範圍內的 operation；剛好
  一個最具體的才用它的樣板（openapi），否則用字面的 path（literal）。不 decode、不改大小寫。
- 粒度是 endpoint 的群組（參數是群組身分的一部分）不含參數；resource_scoped 的群組加上字面 path，
  同一個樣板的不同物件不合併。
"""

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from uuid import UUID

from secscan.core.json_types import JsonObject
from secscan.findings.domain.taxonomy import FINGERPRINT_VERSION, FindingKind
from secscan.grants.domain.matching import Route, parse_route
from secscan.grants.domain.scope import InvalidScopeError
from secscan.scans.domain.coverage import FrozenOperation, OperationRoutes, most_specific


class RouteSource(StrEnum):
    OPENAPI = "openapi"
    LITERAL = "literal"


@dataclass(frozen=True, slots=True)
class Position:
    route: str
    source: RouteSource

    @property
    def templated(self) -> bool:
        """route 是含佔位符的規格樣板（字面的 path 帶大括號時不是）。"""
        return self.source is RouteSource.OPENAPI and "{" in self.route


@dataclass(frozen=True, slots=True)
class FingerprintInputs:
    target_id: UUID
    kind: FindingKind
    rule_group: str
    method: str
    route: str
    # 含佔位符的樣板和字面的 path 即使文字相同也不同（例如字面的 `/orders/{id}`）；沒有佔位符的
    # operation 和字面 path 相同，有沒有規格的掃描都是同一個。
    route_templated: bool
    parameter_location: str | None
    parameter_name: str | None
    auth_role: str
    # 帶認證的身分在這個 run 中確實有效（anonymous 一律是 True）；失效或不明的觀察是另一個 finding。
    auth_verified: bool
    resource: str | None

    def document(self) -> JsonObject:
        return {
            "v": FINGERPRINT_VERSION,
            "target_id": str(self.target_id),
            "kind": self.kind.value,
            "rule_group": self.rule_group,
            "method": self.method,
            "route": self.route,
            "route_templated": self.route_templated,
            "parameter_location": self.parameter_location,
            "parameter_name": self.parameter_name,
            "auth": {"role": self.auth_role, "verified": self.auth_verified},
            "resource": self.resource,
        }


def fingerprint(inputs: FingerprintInputs) -> str:
    encoded = json.dumps(
        inputs.document(), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


type _Shape = tuple[str, int, bool]


@dataclass(frozen=True, slots=True)
class RouteIndex:
    """operation 依 (method, 段數, 結尾斜線) 分組：不寬鬆的比對要求這三者相同，所以只比同一組，
    結果和比對全部相同（一個 run 最多約 2 萬個觀察、1,000 個 operation，連結時持有 run 的鎖）。
    """

    groups: Mapping[_Shape, OperationRoutes]

    @classmethod
    def of(cls, routes: OperationRoutes) -> "RouteIndex":
        groups: dict[_Shape, list[tuple[FrozenOperation, Route]]] = {}
        for operation, route in routes:
            shape = (operation.method, len(route.segments), route.trailing_slash)
            groups.setdefault(shape, []).append((operation, route))
        return cls(MappingProxyType({shape: tuple(items) for shape, items in groups.items()}))

    def candidates(self, method: str, path: Route) -> OperationRoutes:
        return self.groups.get((method, len(path.segments), path.trailing_slash), ())


def position(index: RouteIndex, method: str, path: str) -> Position:
    """觀察的 route：剛好一個最具體的 operation 才用樣板（不猜是哪一個）。"""
    if not index.groups or "{" in path or "}" in path:
        # 字面的 path 帶大括號時不當成佔位符解析。
        return Position(path, RouteSource.LITERAL)
    try:
        parsed = parse_route(path)
    except InvalidScopeError:
        # grant 語法不接受的 path（編碼、空段等）：不會是任何 operation，保持字面。
        return Position(path, RouteSource.LITERAL)
    matched = most_specific(index.candidates(method, parsed), method, parsed)
    if len(matched) != 1:
        return Position(path, RouteSource.LITERAL)
    return Position(matched[0].path, RouteSource.OPENAPI)
