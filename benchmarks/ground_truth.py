"""ground truth 與人工標記的格式（SECURITY_AND_TESTING.md §5.2、§7；docs/DECISIONS.md §29）。

T31 只定義格式、載入與檢查；正式的比對檔由 T27 依 cases.py 的語意撰寫並凍結（status: frozen）。
不以「某掃描器報了」當作標籤：案例由人工標記，比對條件只決定哪些 finding 屬於這個案例。

- ground truth：每個靶場一份。案例有 kind、支援範圍（supported、unsupported、platform_blocked）、
  holdout、適用的 auth role、存在於哪些版本，以及比對條件（rule group 必填，其餘選填）。
- adjudications：沒有對上任何案例的 security finding 的人工裁定（真的另一個問題、誤報、不是安全
  問題）；issue 讓多個 finding 歸到同一個議題（§7.1：同一個真實問題只算一次）。
- pair labels：去重的人工標記（合併是否正確、哪些應該合併卻沒有合併）。
"""

import hashlib
from enum import StrEnum
from pathlib import Path
from typing import Literal, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictStr,
    ValidationError,
    model_validator,
)

from benchmarks.models import Signature
from benchmarks.spec import TargetKind, Variant, validation_summary
from benchmarks.strict_yaml import StrictYamlError, load_strict_yaml

CASE_ID = r"^[A-Za-z0-9_.-]{1,64}$"
ANONYMOUS = "anonymous"


class TruthError(ValueError):
    """ground truth 或標記檔不合規則。"""


class CaseKind(StrEnum):
    SECURITY = "security"
    CONTRACT = "contract"
    ROBUSTNESS = "robustness"


class Support(StrEnum):
    SUPPORTED = "supported"
    # 不在 P0 引擎的能力範圍（例如 BOLA、mass assignment）：不計入 recall 的分母，另外列出。
    UNSUPPORTED = "unsupported"
    # strict-1 的 guard 擋下、不到達靶機（§21.5、§22）：不計入掃描器的漏報。
    PLATFORM_BLOCKED = "platform_blocked"


class TruthStatus(StrEnum):
    DRAFT = "draft"
    FROZEN = "frozen"


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Matcher(_Strict):
    """finding 屬於案例的條件：給定的欄位都要相等（parameter_location 是可接受的清單）。"""

    rule_group: StrictStr = Field(min_length=1)
    method: StrictStr | None = None
    route: StrictStr | None = None
    parameter_location: tuple[StrictStr, ...] | None = Field(default=None, min_length=1)
    parameter_name: StrictStr | None = None

    def matches(self, signature: Signature) -> bool:
        return (
            self.rule_group == signature.rule_group
            and self.method in {None, signature.method}
            and self.route in {None, signature.route}
            and (
                self.parameter_location is None
                or signature.parameter_location in self.parameter_location
            )
            and self.parameter_name in {None, signature.parameter_name}
        )


class Case(_Strict):
    id: StrictStr = Field(pattern=CASE_ID)
    kind: CaseKind
    support: Support
    holdout: StrictBool
    auth_role: StrictStr = ANONYMOUS
    present_in: tuple[Variant, ...] = Field(min_length=1)
    matchers: tuple[Matcher, ...] = ()

    @model_validator(mode="after")
    def _matchable(self) -> Self:
        if (
            self.kind is CaseKind.SECURITY
            and self.support is Support.SUPPORTED
            and not self.matchers
        ):
            raise TruthError("supported 的 security 案例必須有比對條件")
        if len(set(self.present_in)) != len(self.present_in):
            raise TruthError("present_in 不可重複")
        return self


class GroundTruth(_Strict):
    version: Literal[1]
    status: TruthStatus
    target: TargetKind
    cases: tuple[Case, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        ids = [case.id for case in self.cases]
        if len(set(ids)) != len(ids):
            raise TruthError("案例的 id 不可重複")
        owners: dict[Matcher, str] = {}
        for case in self.cases:
            for matcher in case.matchers:
                if owners.setdefault(matcher, case.id) != case.id:
                    raise TruthError("兩個案例有相同的比對條件（ground truth 有歧義）")
        return self


class SignatureIn(_Strict):
    rule_group: StrictStr
    method: StrictStr
    route: StrictStr
    parameter_location: StrictStr | None = None
    parameter_name: StrictStr | None = None

    def signature(self) -> Signature:
        return Signature(
            rule_group=self.rule_group,
            method=self.method,
            route=self.route,
            parameter_location=self.parameter_location,
            parameter_name=self.parameter_name,
        )


class Label(StrEnum):
    TRUE_EXTRA = "true_extra"
    FALSE_POSITIVE = "false_positive"
    NOT_SECURITY = "not_security"


class Adjudication(_Strict):
    target: TargetKind
    variant: Variant
    finding: SignatureIn
    label: Label
    issue: StrictStr | None = Field(default=None, pattern=CASE_ID)

    @model_validator(mode="after")
    def _issue(self) -> Self:
        if (self.label is Label.NOT_SECURITY) != (self.issue is None):
            raise TruthError("true_extra 與 false_positive 必須有 issue；not_security 不給")
        return self


class Adjudications(_Strict):
    version: Literal[1]
    items: tuple[Adjudication, ...] = ()

    @model_validator(mode="after")
    def _unique(self) -> Self:
        keys = [(item.target, item.variant, item.finding) for item in self.items]
        if len(set(keys)) != len(keys):
            raise TruthError("同一個 finding 只能裁定一次")
        return self


class MergeLabel(_Strict):
    target: TargetKind
    finding: SignatureIn
    correct: StrictBool


class MissedMerge(_Strict):
    target: TargetKind
    first: SignatureIn
    second: SignatureIn


class PairLabels(_Strict):
    """complete：missed 已列出所有應合併卻沒有合併的 pair（否則 dedup recall 是 N/A）。"""

    version: Literal[1]
    complete: StrictBool
    merged: tuple[MergeLabel, ...] = ()
    missed: tuple[MissedMerge, ...] = ()


def load_ground_truth(path: Path) -> tuple[GroundTruth, str]:
    content = path.read_bytes()
    return _parse(GroundTruth, content), hashlib.sha256(content).hexdigest()


def load_adjudications(path: Path) -> tuple[Adjudications, str]:
    content = path.read_bytes()
    return _parse(Adjudications, content), hashlib.sha256(content).hexdigest()


def load_pair_labels(path: Path) -> tuple[PairLabels, str]:
    content = path.read_bytes()
    return _parse(PairLabels, content), hashlib.sha256(content).hexdigest()


def _parse[T: BaseModel](model: type[T], content: bytes) -> T:
    try:
        document = load_strict_yaml(content)
    except StrictYamlError as error:
        raise TruthError(str(error)) from None
    try:
        return model.model_validate(document)
    except ValidationError as error:
        raise TruthError(validation_summary(error)) from None
