"""誰可以解密原始證據、報告內容與人工複測摘錄（KEY-03；docs/DECISIONS.md §30.2）。

- 目標的 secret 仍只有 runner 解密（tests/unit/test_secret_reveal_callers.py）。
- 報告內容與摘錄（unseal）：只有報告下載、人工 triage 與本機 CLI（換版、匯出）。
- 原始證據（unseal_stream、read_stream_header）：只有 runner（加密之後的驗證、清除）與 CLI。
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


def test_only_report_downloads_triage_and_the_cli_open_content() -> None:
    assert _users("unseal") <= CONTENT_READERS


def test_only_the_runner_and_the_cli_open_raw_evidence() -> None:
    assert _users("unseal_stream") <= EVIDENCE_READERS
    assert _users("read_stream_header") <= EVIDENCE_READERS


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
