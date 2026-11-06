"""舊認證設定若與內部 header 衝突，啟動綁定明確失敗、不回傳密文。"""

from types import SimpleNamespace
from unittest.mock import Mock, create_autospec
from uuid import uuid4

import pytest
from sqlalchemy.orm import Session

from secscan.scans.domain.lifecycle import RunErrorCode
from secscan.scans.progress import LockedScan
from secscan.scans.queue import QueueOperations
from tests.unit.grants.test_lifecycle import LAB


@pytest.mark.parametrize("header", ["X-ZAP-Scan-ID", "x-zap-scan-id", "X-Zap-Scan-Id"])
def test_legacy_rule_header_credentials_fail_closed_at_launch(header: str) -> None:
    session = Mock(spec=Session)
    session.execute.return_value.first.return_value = SimpleNamespace(
        type="api_key_header", header_name=header, encrypted_secret=b"opaque-test-token"
    )
    scan = create_autospec(LockedScan, instance=True)
    scan.auth_profile_id, scan.auth_profile_version = uuid4(), 1

    error, secret = QueueOperations(session, lab=LAB)._binding(scan, read_secret=True)

    assert error is RunErrorCode.PLAN_REJECTED
    assert secret is None


def test_regular_api_key_header_still_returns_the_sealed_binding() -> None:
    session = Mock(spec=Session)
    session.execute.return_value.first.return_value = SimpleNamespace(
        type="api_key_header", header_name="X-API-Key", encrypted_secret=b"opaque-test-token"
    )
    scan = create_autospec(LockedScan, instance=True)
    scan.auth_profile_id, scan.auth_profile_version = uuid4(), 1

    error, secret = QueueOperations(session, lab=LAB)._binding(scan, read_secret=True)

    assert error is None
    assert secret is not None
    assert secret.credential.wire_header == "X-API-Key"
    assert secret.token == b"opaque-test-token"


def test_new_scan_binding_rejects_a_legacy_reserved_header(monkeypatch: pytest.MonkeyPatch) -> None:
    from secscan.api_keys.domain import Principal, Role
    from secscan.auth_profiles.domain.credentials import AuthType, Credential
    from secscan.auth_profiles.domain.model import AuthProfile
    from secscan.core.errors import AppError, ErrorCode
    from secscan.grants.domain.matching import ScopeRules
    from secscan.scans.domain.request import ScanRequest
    from secscan.scans.service import ScanService
    from secscan.targets.domain import Target

    profile = create_autospec(AuthProfile, instance=True)
    profile.id, profile.project_id, profile.target_id = uuid4(), uuid4(), uuid4()
    profile.current.definition.credential = Credential(AuthType.API_KEY_HEADER, "X-ZAP-Scan-ID")
    request = create_autospec(ScanRequest, instance=True)
    request.auth_profile_id = profile.id
    target = create_autospec(Target, instance=True)
    target.id = profile.target_id
    principal = Principal(uuid4(), Role.OPERATOR, profile.project_id)
    service = ScanService(Mock(spec=Session), lab=LAB)
    monkeypatch.setattr(service._profiles, "get", lambda _: profile)
    monkeypatch.setattr(service._profiles, "lock", lambda _, **kwargs: profile)

    with pytest.raises(AppError) as caught:
        service._auth(principal, request, target, ScopeRules((), True, (), frozenset({"GET"})))

    assert caught.value.status_code == 422
    assert caught.value.code is ErrorCode.INVALID_REQUEST
