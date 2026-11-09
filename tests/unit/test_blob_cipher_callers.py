"""誰可以解密原始證據、報告內容與人工複測摘錄（KEY-03；docs/DECISIONS.md §30.2）。

- 目標的 secret 仍只有 runner 解密（tests/unit/test_secret_reveal_callers.py）。
- 報告內容與摘錄（unseal）：只有報告下載與人工 triage（換版用 rotate，不回傳明文）。
- 原始證據（unseal_stream、read_stream_header）：只有 runner/evidence.py（runner 與 CLI 都經由它）。
- 建立 cipher：證據的只有 runner 的入口與 CLI；內容的只有 API、worker 的入口與 CLI。
blob_cipher 自己（rotate 會先 unseal）不算。
"""

from tests.unit.source_support import SOURCE_ROOT, modules_calling, modules_using

CIPHER_MODULE = "security/blob_cipher.py"
CONTENT_READERS = {
    "reports/service.py",
    "triage/service.py",
    "cli/keys.py",
}
EVIDENCE_READERS = {
    "runner/evidence.py",
    "cli/evidence.py",
}


def _users(attribute: str) -> set[str]:
    return modules_using(attribute) - {CIPHER_MODULE}


def test_only_report_downloads_and_triage_open_content() -> None:
    """換版用 rotate（不回傳明文）；只有這兩個 service 解密內容給 API。"""
    assert _users("unseal") == {"reports/service.py", "triage/service.py"}
    assert _users("unseal") <= CONTENT_READERS


def test_only_the_evidence_vault_opens_raw_evidence() -> None:
    """runner（加密之後的驗證、換版）與 CLI 的匯出都經由 runner/evidence.py。"""
    assert _users("unseal_stream") == {"runner/evidence.py"}
    assert _users("read_stream_header") == {"runner/evidence.py"}
    assert _users("unseal_stream") <= EVIDENCE_READERS


def test_only_the_api_the_worker_and_local_commands_build_the_content_cipher() -> None:
    assert modules_calling("content_cipher") - {"security/key_rings.py"} == {
        "main.py",
        "cli/services.py",
        "cli/keys.py",
        "migrations/versions/v0022_sealed_content.py",
    }


def test_only_report_and_triage_routes_receive_the_content_cipher() -> None:
    users = {
        path.relative_to(SOURCE_ROOT).as_posix()
        for path in SOURCE_ROOT.rglob("*.py")
        if "CurrentContentCipher" in path.read_text(encoding="utf-8")
    }
    assert users == {"findings/content_cipher.py", "reports/router.py", "triage/router.py"}


def test_only_the_runner_and_its_cli_build_the_evidence_cipher() -> None:
    assert modules_calling("evidence_cipher") - {"security/key_rings.py"} <= {
        "cli/services.py",
        "cli/evidence.py",
    }


def test_the_api_and_the_worker_never_read_the_evidence_keys() -> None:
    """API（main.py）與 worker 不讀 EVIDENCE_ENCRYPTION_KEYS；runner 不讀內容的金鑰。"""
    readers = {
        path.relative_to(SOURCE_ROOT).as_posix()
        for path in SOURCE_ROOT.rglob("*.py")
        if "evidence_encryption_keys" in path.read_text(encoding="utf-8")
    }
    assert readers == {"core/config.py", "cli/services.py", "cli/evidence.py", "cli/keys.py"}
    for path in (SOURCE_ROOT / "runner").rglob("*.py"):
        assert "content_encryption_keys" not in path.read_text(encoding="utf-8"), path
