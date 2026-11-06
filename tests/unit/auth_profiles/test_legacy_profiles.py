"""舊 profile 可讀、可換金鑰與修復；不可保留衝突 header 建立新版本。"""

from datetime import UTC, datetime
from unittest.mock import Mock
from uuid import uuid4

import pytest
from sqlalchemy.orm import Session

from secscan.auth_profiles.domain.credentials import AuthType, Credential, SecretValue, check_secret
from secscan.auth_profiles.domain.errors import InvalidAuthProfileError
from secscan.auth_profiles.domain.model import (
    ProfileDefinition,
    VersionChange,
    plan_version,
    secret_context,
)
from secscan.auth_profiles.models import AuthProfileVersionModel
from secscan.auth_profiles.repository import AuthProfileRepository, _version
from tests.secret_support import shared_cipher
from tests.unit.auth_profiles.test_model import ME, OTHER_PREFLIGHT


@pytest.mark.parametrize("erased", [True, False])
def test_legacy_version_metadata_remains_readable(erased: bool) -> None:
    row = AuthProfileVersionModel(
        profile_id=uuid4(),
        version=1,
        type="api_key_header",
        header_name="X-ZAP-Scan-ID",
        preflight_method="GET",
        preflight_path="/me",
        preflight_expected_status=200,
        preflight_expected_json={"/status": "success"},
        created_by_key_id=uuid4(),
        created_at=datetime.now(UTC),
        secret_erased_at=datetime.now(UTC) if erased else None,
    )
    version = _version(row)
    assert version.definition.credential.header_name == "X-ZAP-Scan-ID"
    assert version.secret_configured is not erased


def test_legacy_secret_can_be_loaded_and_rotated_without_changing_context() -> None:
    profile_id = uuid4()
    context = f"auth_profile:{profile_id}:api_key_header:X-ZAP-Scan-ID"
    cipher = shared_cipher()
    token = cipher.seal("synthetic-legacy-canary", context=context)
    session = Mock(spec=Session)
    session.execute.side_effect = [
        Mock(),
        [(profile_id, 1, "api_key_header", "X-ZAP-Scan-ID", token)],
    ]

    [secret] = AuthProfileRepository(session).secrets_for_update()
    rotated = cipher.rotate(secret.token, context=secret.context)

    assert secret.context == context
    assert cipher.reveal(rotated, context=context) == "synthetic-legacy-canary"


def test_legacy_profile_can_be_repaired_with_a_new_header_and_secret() -> None:
    current = ProfileDefinition(Credential(AuthType.API_KEY_HEADER, "X-ZAP-Scan-ID"), ME)
    change = VersionChange(header_name="X-API-Key", secret=SecretValue("new-synthetic-canary"))
    plan = plan_version(current, change)
    assert plan.definition.credential.header_name == "X-API-Key"
    assert plan.new_secret is change.secret
    assert secret_context(uuid4(), current.credential).endswith(":X-ZAP-Scan-ID")


def test_legacy_profile_cannot_keep_the_reserved_header_in_a_new_version() -> None:
    current = ProfileDefinition(Credential(AuthType.API_KEY_HEADER, "X-ZAP-Scan-ID"), ME)
    with pytest.raises(InvalidAuthProfileError, match="header_name"):
        plan_version(current, VersionChange(preflight=OTHER_PREFLIGHT))


@pytest.mark.parametrize("header", ["X-ZAP-Scan-ID", "x-zap-scan-id", "X-Zap-Scan-Id"])
def test_new_secret_validation_rejects_reserved_headers(header: str) -> None:
    credential = Credential(AuthType.API_KEY_HEADER, header)
    with pytest.raises(InvalidAuthProfileError, match="header_name"):
        check_secret(credential, SecretValue("123456"))


def test_legacy_header_cannot_be_formatted_for_a_target_request() -> None:
    from secscan.auth_profiles.domain.credentials import header_line, masking_values

    credential = Credential(AuthType.API_KEY_HEADER, "X-ZAP-Scan-ID")
    secret = SecretValue("synthetic-legacy-canary")
    with pytest.raises(InvalidAuthProfileError, match="header_name"):
        header_line(credential, secret)
    assert masking_values(credential, secret) == (secret.value,)


def test_new_profile_cannot_use_the_reserved_header() -> None:
    from secscan.auth_profiles.domain.model import build_profile
    from tests.unit.auth_profiles.test_model import KEY_ID, _input

    request = _input(type=AuthType.API_KEY_HEADER, header_name="X-ZAP-Scan-ID")
    with pytest.raises(InvalidAuthProfileError, match="header_name"):
        build_profile(request, target_id=uuid4(), created_by_key_id=KEY_ID)
