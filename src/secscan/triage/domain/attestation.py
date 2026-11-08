"""人工複測聲明（attestation）的遮罩與一致性檢查（docs/DECISIONS.md §28.2）。純函式。

人工複測證據是**操作者聲明**：複測不經過平台與 guard，平台不代為重送請求、沒有流量紀錄可比對，
所以這裡的檢查只能擋下明顯不一致、過時或對象錯誤的聲明，不能證明摘錄的真實性。問責靠不可變的
事件（actor key、時間、檢查清單與摘錄的 sha256）與 audit。

處理順序：摘錄先以 display_text 統一換行、換掉換行與 tab 以外的控制字元，再以 redact_text 遮罩
已知的秘密樣式；之後才做一致性檢查與計算雜湊（雜湊是實際保存的內容）。
"""

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from urllib.parse import unquote, urlsplit

from secscan.core.json_types import JsonObject
from secscan.core.text import display_text, require_multiline_text, require_text
from secscan.findings.domain.fingerprint import RouteSource
from secscan.findings.domain.triage import (
    REQUEST_EXCERPT_MAX_BYTES,
    RESPONSE_EXCERPT_MAX_BYTES,
    EvidenceProvenance,
)
from secscan.security.redaction import redact_text

PERFORMED_BY_MAX_LENGTH = 100
PROCEDURE_MAX_LENGTH = 1000
ROLE_MAX_LENGTH = 64
ACCEPTED_RESULT = "not_reproduced"
CHECKS_VERSION = 1
DEFAULT_HTTP_PORT = 80
# 平台實際做過的檢查（寫進事件與 audit，日後加檢查時 checks_version 跟著加一）。
PLATFORM_CHECKS = (
    "request_line_matches_route",
    "host_matches_target",
    "parameter_present",
    "response_status_line",
    "role_matches",
    "time_within_bounds",
    "result_not_reproduced",
    "size_within_limits",
)
_STATUS_LINE = re.compile(r"HTTP/(?:1\.[01]|2(?:\.0)?|3) [1-5][0-9]{2}(?: .*)?")
_TEMPLATE_SEGMENT = re.compile(r"\{[^/{}]+\}")


class AttestationProblem(StrEnum):
    PERFORMED_BY_INVALID = "performed_by_invalid"
    PROCEDURE_INVALID = "procedure_invalid"
    RESULT_NOT_ACCEPTED = "result_not_accepted"
    ROLE_MISMATCH = "role_mismatch"
    PERFORMED_IN_FUTURE = "performed_in_future"
    PERFORMED_BEFORE_LAST_OBSERVATION = "performed_before_last_observation"
    EXCERPT_TOO_LARGE = "excerpt_too_large"
    REQUEST_LINE_MISMATCH = "request_line_mismatch"
    HOST_MISMATCH = "host_mismatch"
    PARAMETER_MISSING = "parameter_missing"
    RESPONSE_STATUS_LINE_MISSING = "response_status_line_missing"


class AttestationError(ValueError):
    def __init__(self, problems: tuple[AttestationProblem, ...]) -> None:
        super().__init__(", ".join(problem.value for problem in problems))
        self.problems = problems


@dataclass(frozen=True, slots=True)
class Attestation:
    """client 提交的聲明（只有這些欄位；actor、provenance 與檢查清單由平台填寫）。"""

    performed_at: datetime
    performed_by: str
    procedure: str
    result: str
    auth_role: str
    request_excerpt: str
    response_excerpt: str


@dataclass(frozen=True, slots=True)
class FindingLocation:
    method: str
    route: str
    route_source: RouteSource
    parameter_name: str | None
    auth_role: str


@dataclass(frozen=True, slots=True)
class TargetHost:
    host: str
    port: int


@dataclass(frozen=True, slots=True)
class CheckedAttestation:
    performed_at: datetime
    performed_by: str
    procedure: str
    auth_role: str
    request_excerpt: str
    response_excerpt: str

    @property
    def request_sha256(self) -> str:
        return _sha256(self.request_excerpt)

    @property
    def response_sha256(self) -> str:
        return _sha256(self.response_excerpt)

    def evidence(self) -> JsonObject:
        """事件中保存的 metadata：不含摘錄內容（摘錄另存，T23a 可以加密與清除）。"""
        return {
            "method": "manual_retest",
            "provenance": EvidenceProvenance.OPERATOR_SUPPLIED.value,
            "performed_at": self.performed_at.isoformat(),
            "performed_by": self.performed_by,
            "procedure": self.procedure,
            "result": ACCEPTED_RESULT,
            "role": self.auth_role,
            "request_excerpt_sha256": self.request_sha256,
            "request_excerpt_bytes": _bytes(self.request_excerpt),
            "response_excerpt_sha256": self.response_sha256,
            "response_excerpt_bytes": _bytes(self.response_excerpt),
            "checks_version": CHECKS_VERSION,
            "platform_checks": list(PLATFORM_CHECKS),
        }


def check_attestation(
    attestation: Attestation,
    location: FindingLocation,
    target: TargetHost,
    *,
    now: datetime,
    last_observed_at: datetime | None,
) -> CheckedAttestation:
    """遮罩並檢查一致性；不符時拋 AttestationError（一次列出所有原因）。"""
    problems: list[AttestationProblem] = []
    performed_by = _single_line(attestation.performed_by, problems)
    procedure = _multi_line(attestation.procedure, problems)
    if attestation.result != ACCEPTED_RESULT:
        problems.append(AttestationProblem.RESULT_NOT_ACCEPTED)
    if attestation.auth_role != location.auth_role:
        problems.append(AttestationProblem.ROLE_MISMATCH)
    if attestation.performed_at > now:
        problems.append(AttestationProblem.PERFORMED_IN_FUTURE)
    if last_observed_at is not None and attestation.performed_at < last_observed_at:
        problems.append(AttestationProblem.PERFORMED_BEFORE_LAST_OBSERVATION)
    request = mask_excerpt(attestation.request_excerpt, REQUEST_EXCERPT_MAX_BYTES)
    response = mask_excerpt(attestation.response_excerpt, RESPONSE_EXCERPT_MAX_BYTES)
    if request is None or response is None:
        problems.append(AttestationProblem.EXCERPT_TOO_LARGE)
    else:
        problems.extend(_request_problems(request, location, target))
        if not _STATUS_LINE.fullmatch(_first_line(response)):
            problems.append(AttestationProblem.RESPONSE_STATUS_LINE_MISSING)
    if problems or request is None or response is None:
        raise AttestationError(tuple(dict.fromkeys(problems)))
    return CheckedAttestation(
        performed_at=attestation.performed_at,
        performed_by=performed_by,
        procedure=procedure,
        auth_role=attestation.auth_role,
        request_excerpt=request,
        response_excerpt=response,
    )


def mask_excerpt(value: str, max_bytes: int) -> str | None:
    """遮罩後、以 UTF-8 計不超過 max_bytes 的摘錄；超過時回傳 None（不截斷：雜湊要對應原意）。"""
    cleaned, truncated = display_text(value, max_length=max_bytes)
    masked = redact_text(cleaned)
    if truncated or not masked.strip() or _bytes(masked) > max_bytes:
        return None
    return masked


def _single_line(value: str, problems: list[AttestationProblem]) -> str:
    try:
        require_text(value, field="performed_by", max_length=PERFORMED_BY_MAX_LENGTH)
    except ValueError:
        problems.append(AttestationProblem.PERFORMED_BY_INVALID)
        return ""
    return redact_text(value)


def _multi_line(value: str, problems: list[AttestationProblem]) -> str:
    try:
        require_multiline_text(value, field="procedure", max_length=PROCEDURE_MAX_LENGTH)
    except ValueError:
        problems.append(AttestationProblem.PROCEDURE_INVALID)
        return ""
    return redact_text(value)


def _request_problems(
    request: str, location: FindingLocation, target: TargetHost
) -> list[AttestationProblem]:
    problems: list[AttestationProblem] = []
    lines = request.split("\n")
    if not _request_line_matches(lines[0], location):
        problems.append(AttestationProblem.REQUEST_LINE_MISMATCH)
    if not _host_matches(_headers(lines[1:]), target):
        problems.append(AttestationProblem.HOST_MISMATCH)
    if location.parameter_name is not None and location.parameter_name not in request:
        problems.append(AttestationProblem.PARAMETER_MISSING)
    return problems


def _request_line_matches(line: str, location: FindingLocation) -> bool:
    parts = line.strip().split(" ")
    if len(parts) != 3 or not parts[2].startswith("HTTP/") or parts[0] != location.method:
        return False
    target = parts[1]
    path = urlsplit(target).path if "://" in target else target.split("?", 1)[0]
    candidates = {path, unquote(path)}
    if location.route_source is RouteSource.OPENAPI:
        pattern = re.compile(
            "".join(
                "[^/]+" if _TEMPLATE_SEGMENT.fullmatch(piece) else re.escape(piece)
                for piece in re.split(r"(\{[^/{}]+\})", location.route)
            )
        )
        return any(pattern.fullmatch(candidate) for candidate in candidates)
    return location.route in candidates


def _headers(lines: list[str]) -> list[tuple[str, str]]:
    headers: list[tuple[str, str]] = []
    for line in lines:
        if not line.strip():
            break
        name, colon, value = line.partition(":")
        if colon:
            headers.append((name.strip().lower(), value.strip()))
    return headers


def _host_matches(headers: list[tuple[str, str]], target: TargetHost) -> bool:
    hosts = [value.lower() for name, value in headers if name == "host"]
    if len(hosts) != 1:
        return False
    accepted = {f"{target.host}:{target.port}".lower()}
    if target.port == DEFAULT_HTTP_PORT:
        accepted.add(target.host.lower())
    return hosts[0] in accepted


def _first_line(text: str) -> str:
    return text.split("\n", 1)[0].strip()


def _bytes(text: str) -> int:
    return len(text.encode("utf-8"))


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
