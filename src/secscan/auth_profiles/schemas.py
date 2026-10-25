"""認證設定的請求與回應 schema（docs/API_CONTRACT.md §6、§16）。

- 請求只限制型別與長度（在讀進 domain 之前就有上界）；規則由 domain 在權限檢查之後驗證，
  錯誤訊息說明原因、不回顯輸入。
- secret 是 SecretStr：API 文件標成 writeOnly（password），repr 與驗證錯誤都不會顯示它。
- 回應沒有 secret，也沒有由它衍生的值；secret_configured 表示這一版是否還有密文。
"""

from datetime import datetime
from typing import Annotated, Self
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    StrictBool,
    StrictInt,
    StrictStr,
    model_validator,
)

from secscan.auth_profiles.domain.credentials import (
    HEADER_NAME_MAX_LENGTH,
    MAX_SECRET_LENGTH,
    AuthType,
    SecretValue,
)
from secscan.auth_profiles.domain.model import (
    PROFILE_NAME_MAX_LENGTH,
    ROLE_LABEL_MAX_LENGTH,
    AuthProfile,
    ChangeInput,
    PreflightInput,
    ProfileInput,
    ProfileVersion,
)
from secscan.auth_profiles.domain.preflight import (
    EXPECTED_TEXT_MAX_LENGTH,
    MAX_EXPECTED_ITEMS,
    POINTER_MAX_LENGTH,
    ExpectedValue,
    Preflight,
)
from secscan.grants.domain.scope import PATH_MAX_LENGTH

METHOD_TEXT_MAX_LENGTH = 16

Pointer = Annotated[StrictStr, Field(max_length=POINTER_MAX_LENGTH)]
# 布林放在整數之前：JSON 的 true 不會變成 1（smart mode 也是先比對完全相同的型別）。
ExpectedIn = (
    Annotated[StrictStr, Field(max_length=EXPECTED_TEXT_MAX_LENGTH)] | StrictBool | StrictInt
)
SecretText = Annotated[SecretStr, Field(max_length=MAX_SECRET_LENGTH)]
HeaderName = Annotated[StrictStr, Field(max_length=HEADER_NAME_MAX_LENGTH)]


class PreflightIn(BaseModel):
    """preflight 的定義；1 到 16 項的 expected_json 由 domain 檢查（訊息說明為什麼不能是空的）。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    method: StrictStr = Field(max_length=METHOD_TEXT_MAX_LENGTH)
    path: StrictStr = Field(max_length=PATH_MAX_LENGTH)
    expected_status: StrictInt
    expected_json: dict[Pointer, ExpectedIn | None] = Field(max_length=MAX_EXPECTED_ITEMS)

    def to_input(self) -> PreflightInput:
        return PreflightInput(
            method=self.method,
            path=self.path,
            expected_status=self.expected_status,
            expected_json=dict(self.expected_json),
        )


class AuthProfileCreate(BaseModel):
    """建立認證設定（version 1）。api_key_header 才有 header_name。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: StrictStr = Field(max_length=PROFILE_NAME_MAX_LENGTH)
    role_label: StrictStr = Field(max_length=ROLE_LABEL_MAX_LENGTH)
    type: AuthType
    header_name: HeaderName | None = None
    secret: SecretText
    preflight: PreflightIn

    def to_input(self) -> ProfileInput:
        return ProfileInput(
            name=self.name,
            role_label=self.role_label,
            type=self.type,
            header_name=self.header_name,
            secret=SecretValue(self.secret.get_secret_value()),
            preflight=self.preflight.to_input(),
        )


class AuthProfilePatch(BaseModel):
    """產生新版本：省略的欄位沿用目前的版本，不接受 null；其他規則由 domain 檢查。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    type: AuthType | None = None
    header_name: HeaderName | None = None
    secret: SecretText | None = None
    preflight: PreflightIn | None = None

    @model_validator(mode="after")
    def _no_nulls(self) -> Self:
        if any(getattr(self, field) is None for field in self.model_fields_set):
            raise ValueError("欄位不可為 null；不修改的欄位請省略")
        return self

    def to_change(self) -> ChangeInput:
        return ChangeInput(
            type=self.type,
            header_name=self.header_name,
            secret=SecretValue(self.secret.get_secret_value()) if self.secret is not None else None,
            preflight=self.preflight.to_input() if self.preflight is not None else None,
        )


class PreflightOut(BaseModel):
    model_config = ConfigDict(frozen=True)

    method: str
    path: str
    expected_status: int
    expected_json: dict[str, StrictBool | StrictInt | StrictStr | None]

    @classmethod
    def of(cls, preflight: Preflight) -> Self:
        expected: dict[str, ExpectedValue] = dict(preflight.expected_json)
        return cls(
            method=preflight.method,
            path=preflight.path,
            expected_status=preflight.expected_status,
            expected_json=expected,
        )


class AuthProfileVersionOut(BaseModel):
    """一個版本的定義；被取代的版本 secret_configured 為 false，secret_erased_at 是清除的時間。"""

    model_config = ConfigDict(frozen=True)

    version: int
    type: AuthType
    header_name: str | None
    preflight: PreflightOut
    secret_configured: bool
    secret_erased_at: datetime | None
    created_by_key_id: UUID
    created_at: datetime

    @classmethod
    def of(cls, version: ProfileVersion) -> Self:
        definition = version.definition
        return cls(
            version=version.version,
            type=definition.credential.type,
            header_name=definition.credential.header_name,
            preflight=PreflightOut.of(definition.preflight),
            secret_configured=version.secret_configured,
            secret_erased_at=version.secret_erased_at,
            created_by_key_id=version.created_by_key_id,
            created_at=version.created_at,
        )


class AuthProfileOut(BaseModel):
    """profile 與它目前的版本；version_* 是這一版的建立者與時間。"""

    model_config = ConfigDict(frozen=True)

    id: UUID
    target_id: UUID
    project_id: UUID
    name: str
    role_label: str
    created_by_key_id: UUID
    created_at: datetime
    version: int
    type: AuthType
    header_name: str | None
    preflight: PreflightOut
    secret_configured: bool
    version_created_by_key_id: UUID
    version_created_at: datetime

    @classmethod
    def of(cls, profile: AuthProfile) -> Self:
        current = profile.current
        definition = current.definition
        return cls(
            id=profile.id,
            target_id=profile.target_id,
            project_id=profile.project_id,
            name=profile.name,
            role_label=profile.role_label,
            created_by_key_id=profile.created_by_key_id,
            created_at=profile.created_at,
            version=current.version,
            type=definition.credential.type,
            header_name=definition.credential.header_name,
            preflight=PreflightOut.of(definition.preflight),
            secret_configured=current.secret_configured,
            version_created_by_key_id=current.created_by_key_id,
            version_created_at=current.created_at,
        )
