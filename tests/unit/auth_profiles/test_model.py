"""auth profile 的 domain model（docs/DECISIONS.md §12.3、§12.6）。

role_label、名稱、密文與 PATCH 的規則。
"""

import json
from uuid import UUID, uuid4

import pytest

from secscan.auth_profiles.domain.credentials import AuthType, Credential, SecretValue
from secscan.auth_profiles.domain.errors import InvalidAuthProfileError
from secscan.auth_profiles.domain.model import (
    EXPECTED_JSON_MAX_BYTES,
    MAX_ENCRYPTED_SECRET_BYTES,
    PROFILE_NAME_MAX_LENGTH,
    ROLE_LABEL_MAX_LENGTH,
    ChangeInput,
    NewAuthProfile,
    NewProfileVersion,
    PreflightInput,
    ProfileDefinition,
    ProfileInput,
    VersionChange,
    build_profile,
    plan_version,
    secret_context,
)
from secscan.auth_profiles.domain.preflight import Preflight
from secscan.security.secret_cipher import SecretCipher
from tests.secret_support import shared_cipher

CANARY = "canary7f3a"
KEY_ID = uuid4()
ME = Preflight(method="GET", path="/me", expected_status=200, expected_json={"/status": "success"})
OTHER_PREFLIGHT = Preflight(
    method="GET", path="/me", expected_status=200, expected_json={"/data/username": "name1"}
)
BEARER = ProfileDefinition(credential=Credential(AuthType.BEARER), preflight=ME)
API_KEY = ProfileDefinition(
    credential=Credential(AuthType.API_KEY_HEADER, header_name="X-API-Key"), preflight=ME
)
# context 最長的送出方式：api_key_header 加上 64 個字元的 header 名稱。
LONGEST = Credential(AuthType.API_KEY_HEADER, header_name="x" * 64)


def _profile(**overrides: object) -> NewAuthProfile:
    params: dict[str, object] = {
        "target_id": uuid4(),
        "name": "VAmPI 一般使用者",
        "role_label": "standard_user",
        "created_by_key_id": KEY_ID,
    }
    params.update(overrides)
    return NewAuthProfile(**params)  # type: ignore[arg-type]


# --- role_label 與名稱 ----------------------------------------------------------------------


@pytest.mark.parametrize("label", ["standard_user", "admin", "a", "user_a1", "a" * 64])
def test_role_labels_are_lowercase_identifiers(label: str) -> None:
    assert _profile(role_label=label).role_label == label


@pytest.mark.parametrize(
    "label",
    [
        "",
        "Admin",
        "1user",
        "_user",
        "user-a",
        "user a",
        "使用者",
        "a" * (ROLE_LABEL_MAX_LENGTH + 1),
    ],
)
def test_other_role_labels_are_rejected(label: str) -> None:
    with pytest.raises(InvalidAuthProfileError, match="role_label"):
        _profile(role_label=label)


def test_anonymous_is_reserved_for_unauthenticated_scans() -> None:
    with pytest.raises(InvalidAuthProfileError, match="anonymous"):
        _profile(role_label="anonymous")


@pytest.mark.parametrize(
    "name", ["", "   ", "\u3000", "a\nb", "a\u202eb", "x" * (PROFILE_NAME_MAX_LENGTH + 1)]
)
def test_names_are_single_line_text(name: str) -> None:
    with pytest.raises(InvalidAuthProfileError, match="name"):
        _profile(name=name)


# --- 密文 -----------------------------------------------------------------------------------


def test_secret_context_binds_the_profile_and_the_credential() -> None:
    """審查發現：只綁 profile 時，能寫 DB 的人可以把密文改用在別的送出方式（例如另一個 header）。
    沿用 secret 只發生在送出方式不變時，所以把 type 與 header_name 也綁進去，不影響複製。"""
    profile_id = UUID("00000000-0000-4000-8000-000000000001")

    assert secret_context(profile_id, BEARER.credential) == (
        "auth_profile:00000000-0000-4000-8000-000000000001:bearer:-"
    )
    assert secret_context(profile_id, API_KEY.credential) == (
        "auth_profile:00000000-0000-4000-8000-000000000001:api_key_header:X-API-Key"
    )


def test_the_longest_context_is_accepted_by_the_cipher() -> None:
    context = secret_context(uuid4(), LONGEST)

    assert (
        shared_cipher().reveal(shared_cipher().seal("k", context=context), context=context) == "k"
    )


def test_a_new_version_only_accepts_fernet_tokens() -> None:
    """程式錯誤把明文直接存進去時，在送進 DB 之前就擋下（DB 另有 CHECK）。"""
    with pytest.raises(ValueError, match="Fernet"):
        NewProfileVersion(
            definition=BEARER, encrypted_secret=CANARY.encode(), created_by_key_id=KEY_ID
        )
    with pytest.raises(ValueError, match="bytes"):
        NewProfileVersion(
            definition=BEARER,
            encrypted_secret=b"gAAAAA" + b"x" * MAX_ENCRYPTED_SECRET_BYTES,
            created_by_key_id=KEY_ID,
        )


def test_the_largest_secret_fits_in_the_column() -> None:
    """每個字元都要在 JSON 中跳脫（"）時最長；長度上限由這個情況推算。"""
    cipher: SecretCipher = shared_cipher()
    token = cipher.seal('"' * 4096, context=secret_context(uuid4(), LONGEST))

    assert len(token) == MAX_ENCRYPTED_SECRET_BYTES
    NewProfileVersion(definition=API_KEY, encrypted_secret=token, created_by_key_id=KEY_ID)


def test_the_largest_expected_json_fits_in_the_column() -> None:
    """16 項、key 與值都用 4 bytes 的字元填滿上限：jsonb 的文字形式仍在 DB 的上限內。"""
    wide = "\U0001d11e"
    checks = {f"/{index:02d}{wide * 253}": wide * 256 for index in range(16)}
    preflight = Preflight(method="GET", path="/me", expected_status=200, expected_json=checks)

    encoded = json.dumps(dict(preflight.expected_json), ensure_ascii=False).encode()

    assert len(encoded) <= EXPECTED_JSON_MAX_BYTES


def test_ciphertext_is_hidden_from_repr() -> None:
    token = shared_cipher().seal(CANARY, context=secret_context(uuid4(), BEARER.credential))

    version = NewProfileVersion(definition=BEARER, encrypted_secret=token, created_by_key_id=KEY_ID)

    assert token.decode() not in repr(version)


# --- PATCH 的規則 ---------------------------------------------------------------------------


def _plan(
    current: ProfileDefinition, **change: object
) -> tuple[ProfileDefinition, bool, tuple[str, ...]]:
    plan = plan_version(current, VersionChange(**change))  # type: ignore[arg-type]
    return plan.definition, plan.new_secret is not None, plan.changed


def _refused(current: ProfileDefinition, **change: object) -> str:
    with pytest.raises(InvalidAuthProfileError) as raised:
        plan_version(current, VersionChange(**change))  # type: ignore[arg-type]
    assert CANARY not in str(raised.value)
    return str(raised.value)


def test_a_change_needs_at_least_one_field() -> None:
    assert "至少" in _refused(BEARER)


def test_a_new_secret_alone_makes_a_new_version() -> None:
    assert _plan(BEARER, secret=SecretValue("new-token")) == (BEARER, True, ("secret",))


def test_a_new_preflight_alone_keeps_the_secret() -> None:
    definition, new_secret, changed = _plan(BEARER, preflight=OTHER_PREFLIGHT)

    assert definition == ProfileDefinition(credential=BEARER.credential, preflight=OTHER_PREFLIGHT)
    assert (new_secret, changed) == (False, ("preflight",))


@pytest.mark.parametrize(
    "change",
    [
        {"preflight": ME},
        {"type": AuthType.BEARER},
        {"type": AuthType.BEARER, "preflight": ME},
    ],
)
def test_nothing_changed_is_refused(change: dict[str, object]) -> None:
    assert "沒有任何變更" in _refused(BEARER, **change)


def test_changing_the_type_needs_a_new_secret() -> None:
    assert "新的 secret" in _refused(BEARER, type=AuthType.COOKIE)


def test_changing_the_type_with_a_matching_secret() -> None:
    definition, new_secret, changed = _plan(
        BEARER, type=AuthType.COOKIE, secret=SecretValue("session=abc")
    )

    assert definition.credential == Credential(AuthType.COOKIE)
    assert (new_secret, changed) == (True, ("type", "secret"))


def test_the_new_secret_must_fit_the_new_type() -> None:
    assert "secret" in _refused(BEARER, type=AuthType.COOKIE, secret=SecretValue(CANARY))


def test_switching_to_api_key_header_needs_a_header_name() -> None:
    assert "header_name" in _refused(BEARER, type=AuthType.API_KEY_HEADER, secret=SecretValue("k"))


def test_switching_to_api_key_header_with_a_name_and_a_secret() -> None:
    definition, new_secret, changed = _plan(
        BEARER, type=AuthType.API_KEY_HEADER, header_name="X-Token", secret=SecretValue("k")
    )

    assert definition.credential == Credential(AuthType.API_KEY_HEADER, header_name="X-Token")
    assert (new_secret, changed) == (True, ("type", "header_name", "secret"))


def test_a_new_api_key_value_keeps_the_header_name() -> None:
    """最常見的情況：只換 API key 的值，header 名稱沿用目前的版本。"""
    assert _plan(API_KEY, secret=SecretValue("k2")) == (API_KEY, True, ("secret",))


def test_renaming_the_header_needs_a_new_secret() -> None:
    assert "新的 secret" in _refused(API_KEY, header_name="X-Token")


def test_renaming_the_header_with_a_secret() -> None:
    definition, _, changed = _plan(API_KEY, header_name="X-Token", secret=SecretValue("k"))

    assert definition.credential.header_name == "X-Token"
    assert changed == ("header_name", "secret")


def test_leaving_api_key_header_drops_the_header_name() -> None:
    definition, _, changed = _plan(API_KEY, type=AuthType.BEARER, secret=SecretValue("token"))

    assert definition.credential == Credential(AuthType.BEARER)
    assert changed == ("type", "header_name", "secret")


def test_only_api_key_header_takes_a_header_name() -> None:
    assert "header_name" in _refused(BEARER, header_name="X-Token", secret=SecretValue("t"))


def test_same_header_name_without_a_secret_is_no_change() -> None:
    assert "沒有任何變更" in _refused(
        API_KEY, type=AuthType.API_KEY_HEADER, header_name="X-API-Key"
    )


def test_the_secret_is_checked_against_the_current_type() -> None:
    assert "secret" in _refused(BEARER, secret=SecretValue(f"Bearer {CANARY}"))


def test_secret_and_preflight_together() -> None:
    _, new_secret, changed = _plan(BEARER, secret=SecretValue("t"), preflight=OTHER_PREFLIGHT)

    assert (new_secret, changed) == (True, ("secret", "preflight"))


def test_changes_hide_the_secret_from_repr() -> None:
    change = VersionChange(secret=SecretValue(CANARY))

    assert CANARY not in repr(change)
    assert CANARY not in repr(plan_version(BEARER, change))


# --- 尚未驗證的輸入（service 在檢查權限之後才建立 domain 物件）------------------------------


def _input(**overrides: object) -> ProfileInput:
    params: dict[str, object] = {
        "name": "VAmPI 一般使用者",
        "role_label": "standard_user",
        "type": AuthType.BEARER,
        "header_name": None,
        "secret": SecretValue(CANARY),
        "preflight": PreflightInput(
            method="GET", path="/me", expected_status=200, expected_json={"/status": "success"}
        ),
    }
    params.update(overrides)
    return ProfileInput(**params)  # type: ignore[arg-type]


def test_build_profile_validates_every_part() -> None:
    target_id = uuid4()

    profile, definition = build_profile(_input(), target_id=target_id, created_by_key_id=KEY_ID)

    assert (profile.target_id, profile.role_label, profile.created_by_key_id) == (
        target_id,
        "standard_user",
        KEY_ID,
    )
    assert definition == ProfileDefinition(credential=Credential(AuthType.BEARER), preflight=ME)


@pytest.mark.parametrize(
    ("overrides", "field"),
    [
        ({"name": " "}, "name"),
        ({"role_label": "Admin"}, "role_label"),
        ({"type": AuthType.API_KEY_HEADER}, "header_name"),
        ({"secret": SecretValue(f"Bearer {CANARY}")}, "secret"),
        (
            {
                "preflight": PreflightInput(
                    method="POST", path="/me", expected_status=200, expected_json={"/a": 1}
                )
            },
            "preflight.method",
        ),
    ],
)
def test_build_profile_rejects_each_part(overrides: dict[str, object], field: str) -> None:
    with pytest.raises(InvalidAuthProfileError) as raised:
        build_profile(_input(**overrides), target_id=uuid4(), created_by_key_id=KEY_ID)

    assert str(raised.value).startswith(field)
    assert CANARY not in str(raised.value)


def test_inputs_hide_the_secret_from_repr() -> None:
    assert CANARY not in repr(_input())
    assert CANARY not in repr(ChangeInput(secret=SecretValue(CANARY)))


def test_change_input_builds_the_preflight() -> None:
    change = ChangeInput(
        preflight=PreflightInput(
            method="GET", path="/me", expected_status=200, expected_json={"/status": "success"}
        )
    ).build()

    assert change == VersionChange(preflight=ME)
    assert ChangeInput(type=AuthType.COOKIE).build() == VersionChange(type=AuthType.COOKIE)
    with pytest.raises(InvalidAuthProfileError, match=r"preflight\.path"):
        ChangeInput(
            preflight=PreflightInput(
                method="GET", path="me", expected_status=200, expected_json={"/a": 1}
            )
        ).build()
