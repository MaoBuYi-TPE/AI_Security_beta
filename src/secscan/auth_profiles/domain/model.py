"""auth profile 的 domain model（docs/DECISIONS.md §12.3、§12.6）。

- profile：屬於一個 target，有名稱與 role_label，建立後不可修改。
- 版本：送出方式（Credential）、preflight 與密文。PATCH 產生新版本，上一版的密文清除，
  所以每個 profile 最多一份密文（DB 以部分唯一索引保證）。
- 密文綁定 profile（secret_context），不綁版本：新版本沿用 secret 時直接複製密文，不必解密。
"""

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from uuid import UUID

from secscan.auth_profiles.domain.credentials import (
    MAX_SECRET_LENGTH,
    AuthType,
    Credential,
    SecretValue,
    check_secret,
)
from secscan.auth_profiles.domain.errors import InvalidAuthProfileError
from secscan.auth_profiles.domain.preflight import ExpectedValue, Preflight
from secscan.core.text import require_text
from secscan.security.secret_cipher import TOKEN_PREFIX, max_sealed_bytes

PROFILE_NAME_MAX_LENGTH = 100
ROLE_LABEL_MAX_LENGTH = 64
_ROLE_LABEL = re.compile(rf"[a-z][a-z0-9_]{{0,{ROLE_LABEL_MAX_LENGTH - 1}}}")
# 未認證的 scan 標記為 anonymous（docs/API_CONTRACT.md §7）。
RESERVED_ROLE_LABELS = frozenset({"anonymous"})
CONTEXT_PREFIX = "auth_profile:"
# expected_json 在 DB 中的上限（jsonb 的文字形式）：最多 16 項，key 與字串值各最多 256 個字元，
# 非 ASCII 的字元最多 4 bytes，最壞約 33 KB（一般不到 1 KB）。DB 的 CHECK 只是最後一道防線。
EXPECTED_JSON_MAX_BYTES = 64 * 1024
# PATCH 的欄位，也是 audit 中 changed 的順序。
CHANGE_FIELDS = ("type", "header_name", "secret", "preflight")


def secret_context(profile_id: UUID) -> str:
    """密文綁定的位置：搬到其他 profile 的密文解不開。"""
    return f"{CONTEXT_PREFIX}{profile_id}"


# 每個字元在 JSON 中都要跳脫時（例如全是 "），值的長度是原本的兩倍；context 的長度固定。
MAX_ENCRYPTED_SECRET_BYTES = max_sealed_bytes(
    context_length=len(secret_context(UUID(int=0))), value_json_bytes=2 * MAX_SECRET_LENGTH
)


def check_role_label(label: str) -> None:
    if _ROLE_LABEL.fullmatch(label) is None:
        raise InvalidAuthProfileError(
            "role_label 只能使用小寫英文字母、數字與 _，以字母開頭，"
            f"最多 {ROLE_LABEL_MAX_LENGTH} 個字元（例如 standard_user）"
        )
    if label in RESERVED_ROLE_LABELS:
        raise InvalidAuthProfileError("role_label 不可以是 anonymous（保留給未認證的 scan）")


def check_profile_name(name: str) -> None:
    try:
        require_text(name, field="name", max_length=PROFILE_NAME_MAX_LENGTH)
    except ValueError as exc:
        raise InvalidAuthProfileError(str(exc)) from None


@dataclass(frozen=True, slots=True)
class ProfileDefinition:
    """一個版本定義的內容（不含 secret）：送出方式與 preflight。"""

    credential: Credential
    preflight: Preflight


@dataclass(frozen=True, slots=True)
class NewAuthProfile:
    target_id: UUID
    name: str
    role_label: str
    created_by_key_id: UUID

    def __post_init__(self) -> None:
        check_profile_name(self.name)
        check_role_label(self.role_label)


@dataclass(frozen=True, slots=True)
class NewProfileVersion:
    """要寫入的版本。密文必須是 Fernet token（不是明文），也不出現在 repr。"""

    definition: ProfileDefinition
    encrypted_secret: bytes = field(repr=False)
    created_by_key_id: UUID

    def __post_init__(self) -> None:
        if not self.encrypted_secret.startswith(TOKEN_PREFIX):
            raise ValueError("encrypted_secret 必須是 Fernet token（不可存明文）")
        if len(self.encrypted_secret) > MAX_ENCRYPTED_SECRET_BYTES:
            raise ValueError(f"encrypted_secret 不可超過 {MAX_ENCRYPTED_SECRET_BYTES:,} bytes")


@dataclass(frozen=True, slots=True)
class ProfileVersion:
    """secret_configured 為 False：這一版已被取代，密文在 secret_erased_at 清除。"""

    profile_id: UUID
    version: int
    definition: ProfileDefinition
    secret_configured: bool
    secret_erased_at: datetime | None
    created_by_key_id: UUID
    created_at: datetime


@dataclass(frozen=True, slots=True)
class AuthProfile:
    """profile 與它目前（最新）的版本。project 由 target 取得，不另外存放。"""

    id: UUID
    target_id: UUID
    project_id: UUID
    name: str
    role_label: str
    created_by_key_id: UUID
    created_at: datetime
    current: ProfileVersion


@dataclass(frozen=True, slots=True)
class StoredSecret:
    """DB 中的一份密文與它的位置（金鑰換版時重新加密用）；密文不出現在 repr。"""

    profile_id: UUID
    version: int
    token: bytes = field(repr=False)


@dataclass(frozen=True, slots=True)
class VersionChange:
    """PATCH 的內容；None 代表沒有給（null 由 schema 拒絕）。"""

    type: AuthType | None = None
    header_name: str | None = None
    secret: SecretValue | None = None
    preflight: Preflight | None = None


@dataclass(frozen=True, slots=True)
class VersionPlan:
    """新版本的定義。new_secret 為 None 時沿用目前的密文（直接複製）；
    changed 依 CHANGE_FIELDS 的順序。
    """

    definition: ProfileDefinition
    new_secret: SecretValue | None
    changed: tuple[str, ...]


def plan_version(current: ProfileDefinition, change: VersionChange) -> VersionPlan:
    """PATCH 的規則（docs/DECISIONS.md §12.6）：沒給的欄位沿用目前的版本，preflight 整份取代；
    改變送出方式時必須附上新的 secret；完全沒有變更時拒絕。"""
    if all(getattr(change, name) is None for name in CHANGE_FIELDS):
        raise InvalidAuthProfileError(
            "至少要修改一個欄位（type、header_name、secret 或 preflight）"
        )
    credential = _next_credential(current.credential, change)
    if credential != current.credential and change.secret is None:
        raise InvalidAuthProfileError("secret：改變 type 或 header_name 時，必須附上新的 secret")
    if change.secret is not None:
        check_secret(credential, change.secret)
    preflight = change.preflight if change.preflight is not None else current.preflight
    definition = ProfileDefinition(credential=credential, preflight=preflight)
    if change.secret is None and definition == current:
        raise InvalidAuthProfileError("沒有任何變更：定義與目前的版本相同，也沒有新的 secret")
    differs = {
        "type": credential.type is not current.credential.type,
        "header_name": credential.header_name != current.credential.header_name,
        "secret": change.secret is not None,
        "preflight": preflight != current.preflight,
    }
    changed = tuple(name for name in CHANGE_FIELDS if differs[name])
    return VersionPlan(definition=definition, new_secret=change.secret, changed=changed)


def _next_credential(current: Credential, change: VersionChange) -> Credential:
    kind = change.type if change.type is not None else current.type
    if kind is not AuthType.API_KEY_HEADER:
        # 有給 header_name 時，Credential 會拒絕：只有 api_key_header 可以指定。
        return Credential(kind, header_name=change.header_name)
    if change.header_name is not None:
        return Credential(kind, header_name=change.header_name)
    if current.type is AuthType.API_KEY_HEADER:
        return Credential(kind, header_name=current.header_name)
    raise InvalidAuthProfileError("header_name：改成 api_key_header 時必須指定")


# --- 尚未驗證的輸入 ---------------------------------------------------------------------------
# schema 只檢查型別與長度；service 在檢查權限之後才建立 domain 物件，不替沒有權限的呼叫者驗證內容。


@dataclass(frozen=True, slots=True)
class PreflightInput:
    method: str
    path: str
    expected_status: int
    expected_json: Mapping[str, ExpectedValue]

    def build(self) -> Preflight:
        return Preflight(
            method=self.method,
            path=self.path,
            expected_status=self.expected_status,
            expected_json=self.expected_json,
        )


@dataclass(frozen=True, slots=True)
class ProfileInput:
    """建立 profile 的輸入；secret 不出現在 repr。"""

    name: str
    role_label: str
    type: AuthType
    header_name: str | None
    secret: SecretValue
    preflight: PreflightInput


@dataclass(frozen=True, slots=True)
class ChangeInput:
    """PATCH 的輸入；None 代表沒有給。"""

    type: AuthType | None = None
    header_name: str | None = None
    secret: SecretValue | None = None
    preflight: PreflightInput | None = None

    def build(self) -> VersionChange:
        return VersionChange(
            type=self.type,
            header_name=self.header_name,
            secret=self.secret,
            preflight=self.preflight.build() if self.preflight is not None else None,
        )


def build_profile(
    request: ProfileInput, *, target_id: UUID, created_by_key_id: UUID
) -> tuple[NewAuthProfile, ProfileDefinition]:
    """驗證建立 profile 的輸入：名稱、role_label、送出方式、secret 與 preflight（依這個順序）。"""
    profile = NewAuthProfile(
        target_id=target_id,
        name=request.name,
        role_label=request.role_label,
        created_by_key_id=created_by_key_id,
    )
    credential = Credential(request.type, header_name=request.header_name)
    check_secret(credential, request.secret)
    definition = ProfileDefinition(credential=credential, preflight=request.preflight.build())
    return profile, definition
