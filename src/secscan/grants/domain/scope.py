"""grant 的範圍、預算與期限（docs/DECISIONS.md §10.3）。

- 結構規則（格式、筆數、重複）放在 dataclass 的 __post_init__：從 DB 讀回的資料也會經過。
- 與申請當下有關的政策（預算上限、期限晚於現在、最長 30 天）放在 resolve_*()，只在申請時
  檢查；日後調整政策，既有的 grant 仍然讀得出來。
- 錯誤訊息只說明欄位、位置與原因，不含輸入內容。
"""

import re
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from ipaddress import IPv4Address
from uuid import UUID

from secscan.core.text import require_text
from secscan.targets.domain import (
    InvalidOriginError,
    LabNetwork,
    Origin,
    parse_ipv4,
    parse_origin,
)

MAX_ALLOWED_ORIGINS = 4
MAX_ALLOWED_IPS = 16
MAX_ALLOWED_PATHS = 256
MAX_EXCLUDED_PATHS = 64
PATH_MAX_LENGTH = 512
AUTHORIZATION_REFERENCE_MAX_LENGTH = 200
MAX_GRANT_WINDOW = timedelta(days=30)
# 預算上限：M0 到 M2 的保守起始值（ARCHITECTURE.md §3.4）；M3 量測後調整時，在 DECISIONS 記錄。
MAX_REQUESTS_PER_SECOND = 2
MAX_REQUESTS = 5_000
MAX_DURATION_SECONDS = 1_500
DELETE_CHARACTER = "\x7f"

# path 的一段：RFC 3986 的 unreserved 與部分 sub-delims。不收 ";"（部分伺服器當成 path 參數）
# 與 "*"（容易被誤認成萬用字元）；percent-encoding 讓同一條 path 有多種寫法，也不收。
_PATH_SEGMENT = re.compile(r"[A-Za-z0-9._~!$&'()+,=:@-]+")
# OpenAPI 的 route 佔位，必須占滿一整段。
_PLACEHOLDER = re.compile(r"\{[A-Za-z_][A-Za-z0-9_]*\}")


class HttpMethod(StrEnum):
    """grant 可以允許的 method。TRACE、CONNECT 一律不接受。"""

    GET = "GET"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"


_METHOD_VALUES = tuple(method.value for method in HttpMethod)


class InvalidScopeError(ValueError):
    """grant 的範圍、預算或期限不合規則。"""


@dataclass(frozen=True, slots=True)
class Scope:
    """grant 允許的範圍；建立後不可變（要改就申請新版本）。"""

    origins: tuple[Origin, ...]
    ips: tuple[IPv4Address, ...]
    paths: tuple[str, ...]
    allow_all_paths: bool
    excluded_paths: tuple[str, ...]
    methods: tuple[HttpMethod, ...]

    def __post_init__(self) -> None:
        _check_count("allowed_origins", self.origins, MAX_ALLOWED_ORIGINS)
        _check_unique("allowed_origins", self.origins)
        _check_count("allowed_ips", self.ips, MAX_ALLOWED_IPS)
        _check_unique("allowed_ips", self.ips)
        if {origin.ip for origin in self.origins if origin.ip is not None} - set(self.ips):
            raise InvalidScopeError(
                "allowed_origins 中 host 是 IP 的 origin，該 IP 必須列在 allowed_ips"
            )
        self._check_paths()
        _check_count("allowed_methods", self.methods, len(HttpMethod))
        _check_unique("allowed_methods", self.methods)

    def _check_paths(self) -> None:
        if self.allow_all_paths and self.paths:
            raise InvalidScopeError("allow_all_paths 為 true 時，allowed_paths 必須是空的")
        if not self.allow_all_paths and not 1 <= len(self.paths) <= MAX_ALLOWED_PATHS:
            raise InvalidScopeError(
                f"allowed_paths 必須有 1 到 {MAX_ALLOWED_PATHS} 個；"
                "要允許全部 path，請改用 allow_all_paths"
            )
        _check_count("excluded_paths", self.excluded_paths, MAX_EXCLUDED_PATHS, minimum=0)
        listed = (("allowed_paths", self.paths), ("excluded_paths", self.excluded_paths))
        for field, paths in listed:
            for position, path in enumerate(paths, start=1):
                check_path(path, label=f"{field} 第 {position} 個")
            _check_unique(field, paths)
        if set(self.paths) & set(self.excluded_paths):
            raise InvalidScopeError("同一個 path 不可同時列在 allowed_paths 與 excluded_paths")


def build_scope(
    *,
    target_origin: Origin,
    origins: Sequence[str],
    ips: Sequence[str],
    paths: Sequence[str],
    allow_all_paths: bool,
    excluded_paths: Sequence[str],
    methods: Sequence[str],
) -> Scope:
    """把申請內容轉成 Scope。

    origin 不合法時拋出 InvalidOriginError，其他問題拋出 InvalidScopeError。
    """
    scope = Scope(
        origins=_parse_origins(origins),
        ips=_parse_ips(ips),
        paths=tuple(paths),
        allow_all_paths=allow_all_paths,
        excluded_paths=tuple(excluded_paths),
        methods=_parse_methods(methods),
    )
    if target_origin not in scope.origins:
        raise InvalidScopeError("allowed_origins 必須包含 target 的 origin")
    return scope


def check_lab(scope: Scope, lab: LabNetwork) -> None:
    """所有 IP 都必須是 LAB_CIDR 內的主機位址；host 是 IP 的 origin 已包含在 allowed_ips 中。"""
    for address in scope.ips:
        lab.check_host(address)


def check_path(path: str, *, label: str) -> None:
    """完整的 literal path，或含整段 {name} 佔位的 route；不接受 regex、萬用字元或編碼。"""
    problem = _path_problem(path)
    if problem is not None:
        raise InvalidScopeError(f"{label}：{problem}")


def _path_problem(path: str) -> str | None:
    if len(path) > PATH_MAX_LENGTH:
        return f"path 不可超過 {PATH_MAX_LENGTH} 個字元"
    if not path.startswith("/"):
        return "path 必須以 / 開頭"
    if not path.isascii() or any(c <= " " or c == DELETE_CHARACTER for c in path):
        return "path 只能使用 ASCII 的可見字元"
    segments = path[1:].split("/")
    if segments[-1] == "":
        segments.pop()  # 根目錄 "/" 或結尾的 "/"
    for segment in segments:
        problem = _segment_problem(segment)
        if problem is not None:
            return problem
    return None


def _segment_problem(segment: str) -> str | None:
    if segment == "":
        return "path 不可有空的段落（//）"
    if segment in {".", ".."}:
        return "path 不可有 . 或 .. 段落"
    if _PLACEHOLDER.fullmatch(segment) or _PATH_SEGMENT.fullmatch(segment):
        return None
    if "{" in segment or "}" in segment:
        return "route 佔位必須占滿一整段，名稱以英文字母或底線開頭（例如 {id}）"
    return "path 含有不允許的字元（不接受 %、\\、?、#、;、* 等）"


def _parse_origins(values: Sequence[str]) -> tuple[Origin, ...]:
    origins: list[Origin] = []
    for position, value in enumerate(values, start=1):
        try:
            origins.append(parse_origin(value))
        except InvalidOriginError as exc:
            raise InvalidOriginError(f"allowed_origins 第 {position} 個：{exc}") from None
    return tuple(origins)


def _parse_ips(values: Sequence[str]) -> tuple[IPv4Address, ...]:
    ips: list[IPv4Address] = []
    for position, value in enumerate(values, start=1):
        try:
            ips.append(parse_ipv4(value))
        except ValueError as exc:
            raise InvalidScopeError(f"allowed_ips 第 {position} 個：{exc}") from None
    return tuple(ips)


def _parse_methods(values: Sequence[str]) -> tuple[HttpMethod, ...]:
    for position, value in enumerate(values, start=1):
        if value not in _METHOD_VALUES:
            raise InvalidScopeError(
                f"allowed_methods 第 {position} 個：只接受 "
                f"{'、'.join(_METHOD_VALUES)}（大小寫必須一致）"
            )
    return tuple(HttpMethod(value) for value in values)


def _check_count(field: str, values: Sequence[object], maximum: int, *, minimum: int = 1) -> None:
    if not minimum <= len(values) <= maximum:
        raise InvalidScopeError(f"{field} 必須有 {minimum} 到 {maximum} 個")


def _check_unique(field: str, values: Sequence[object]) -> None:
    if len(set(values)) != len(values):
        raise InvalidScopeError(f"{field} 不可重複")


# --- 預算 -----------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Budget:
    """跨引擎共用的掃描預算（由 guard 強制）。這裡只檢查是正整數；上限見 resolve_budget()。"""

    requests_per_second: int
    max_requests: int
    max_duration_seconds: int

    def __post_init__(self) -> None:
        for field in ("requests_per_second", "max_requests", "max_duration_seconds"):
            if not _is_positive_int(getattr(self, field)):
                raise InvalidScopeError(f"{field} 必須是正整數")


def resolve_budget(
    *,
    requests_per_second: int | None = None,
    max_requests: int | None = None,
    max_duration_seconds: int | None = None,
) -> Budget:
    """申請的預算：沒指定的項目用上限，指定的項目不可超過上限。"""
    return Budget(
        requests_per_second=_within_cap(
            "requests_per_second", requests_per_second, MAX_REQUESTS_PER_SECOND
        ),
        max_requests=_within_cap("max_requests", max_requests, MAX_REQUESTS),
        max_duration_seconds=_within_cap(
            "max_duration_seconds", max_duration_seconds, MAX_DURATION_SECONDS
        ),
    )


def _within_cap(field: str, value: int | None, cap: int) -> int:
    if value is None:
        return cap
    if not _is_positive_int(value) or value > cap:
        raise InvalidScopeError(f"{field} 必須是 1 到 {cap} 的整數")
    return value


def _is_positive_int(value: object) -> bool:
    # bool 是 int 的子類別：True 不能被當成 1。
    return isinstance(value, int) and not isinstance(value, bool) and value >= 1


# --- 期限 -----------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ValidityWindow:
    """有效期間 [valid_from, valid_until)。

    這裡只檢查帶時區、先後正確；「晚於現在」與最長期間見 resolve_window()。
    """

    valid_from: datetime
    valid_until: datetime

    def __post_init__(self) -> None:
        if self.valid_from.utcoffset() is None or self.valid_until.utcoffset() is None:
            raise InvalidScopeError("valid_from 與 valid_until 必須帶時區")
        if self.valid_from >= self.valid_until:
            raise InvalidScopeError("valid_from 必須早於 valid_until")


def resolve_window(
    valid_from: datetime | None, valid_until: datetime, *, now: datetime
) -> ValidityWindow:
    """申請的期間（UTC）：valid_from 預設為現在；valid_until 必須晚於現在；期間最長 30 天。"""
    if valid_until.utcoffset() is None or (
        valid_from is not None and valid_from.utcoffset() is None
    ):
        raise InvalidScopeError("valid_from 與 valid_until 必須帶時區")
    start = now if valid_from is None else valid_from
    # 先以原本的時區比較：帶時區的 datetime 之間比較與相減不會溢位，換算成 UTC 卻可能會
    # （例如 9999-12-31T23:59:59-05:00）。
    if start >= valid_until:
        raise InvalidScopeError("valid_from 必須早於 valid_until")
    if valid_until <= now:
        raise InvalidScopeError("valid_until 必須晚於現在")
    if valid_until - start > MAX_GRANT_WINDOW:
        raise InvalidScopeError(f"valid_from 到 valid_until 不可超過 {MAX_GRANT_WINDOW.days} 天")
    try:
        return ValidityWindow(
            valid_from=start.astimezone(UTC), valid_until=valid_until.astimezone(UTC)
        )
    except OverflowError:
        raise InvalidScopeError("valid_from 與 valid_until 超出可表示的時間範圍") from None


# --- 申請 -----------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class NewScopeGrant:
    """申請 grant 的內容；範圍、預算與期限都已檢查。version 由 repository 在鎖住 target 後決定。"""

    target_id: UUID
    scope: Scope
    budget: Budget
    window: ValidityWindow
    authorization_reference: str
    requested_by_key_id: UUID

    def __post_init__(self) -> None:
        try:
            require_text(
                self.authorization_reference,
                field="authorization_reference",
                max_length=AUTHORIZATION_REFERENCE_MAX_LENGTH,
            )
        except ValueError as exc:
            raise InvalidScopeError(str(exc)) from None


@dataclass(frozen=True, slots=True)
class GrantRequest:
    """使用者送來的申請內容（尚未檢查）；由 build_new_grant() 套用所有規則。"""

    origins: Sequence[str]
    ips: Sequence[str]
    paths: Sequence[str]
    allow_all_paths: bool
    excluded_paths: Sequence[str]
    methods: Sequence[str]
    authorization_reference: str
    valid_until: datetime
    valid_from: datetime | None = None
    requests_per_second: int | None = None
    max_requests: int | None = None
    max_duration_seconds: int | None = None


def build_new_grant(
    request: GrantRequest,
    *,
    target_id: UUID,
    target_origin: Origin,
    requested_by: UUID,
    now: datetime,
) -> NewScopeGrant:
    """套用範圍、預算與期限的規則。是否在 LAB_CIDR 內由呼叫端以當下的設定另外檢查（check_lab）。"""
    return NewScopeGrant(
        target_id=target_id,
        scope=build_scope(
            target_origin=target_origin,
            origins=request.origins,
            ips=request.ips,
            paths=request.paths,
            allow_all_paths=request.allow_all_paths,
            excluded_paths=request.excluded_paths,
            methods=request.methods,
        ),
        budget=resolve_budget(
            requests_per_second=request.requests_per_second,
            max_requests=request.max_requests,
            max_duration_seconds=request.max_duration_seconds,
        ),
        window=resolve_window(request.valid_from, request.valid_until, now=now),
        authorization_reference=request.authorization_reference,
        requested_by_key_id=requested_by,
    )
