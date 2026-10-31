"""政策選版只在 runner 設定入口預設 strict；未知值啟動失敗。"""

from pathlib import Path

import pytest
from pydantic import ValidationError

from secscan.guard.domain.policy import GuardPolicyVersion
from secscan.runner.config import RunnerSettings


def test_policy_version_defaults_to_strict(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("RUNNER_GUARD_POLICY_VERSION", raising=False)

    assert RunnerSettings().guard_policy_version is GuardPolicyVersion.STRICT


def test_explicit_runner_environment_selects_experimental(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("RUNNER_GUARD_POLICY_VERSION", "encoded-params-1")

    assert RunnerSettings().guard_policy_version is GuardPolicyVersion.ENCODED_PARAMS


def test_unknown_policy_version_does_not_fall_back(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("RUNNER_GUARD_POLICY_VERSION", "encoded-params-2")

    with pytest.raises(ValidationError):
        RunnerSettings()
