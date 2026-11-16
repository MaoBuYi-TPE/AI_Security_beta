"""處理秘密的測試，失敗時不輸出原始值（G1 審查：assert 不得輸出環境變數、ValidationError 或秘密）。

pytest 的 assertion rewriting 會在失敗時印出 assert 的運算元與呼叫的參數（例如 `_found(text, …)` 的
text、`x not in output` 的 output）。T23b-b2 處理秘密、canary、環境變數或設定錯誤的測試模組因此在
docstring 宣告關閉改寫的標記（MARKER）：失敗時只顯示原始碼與（只有名稱的）訊息。

這個模組本身不處理秘密，docstring 不寫出那個標記（pytest 只看 docstring 是否含有它）：自己的 assert
照常改寫，失敗時看得到缺少標記的模組名稱（第二輪程式碼審查 LOW-4）。
"""

import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
# pytest 關閉 assertion rewriting 的標記（分成兩段：這個模組自己的原始碼不必含有完整的字）。
MARKER = "PYTEST_" + "DONT_REWRITE"
# 正向對照中刻意失敗的 assert 的期待值。
EXPECTED_BY_THE_CONTROL = 2
SECRET_HANDLING_MODULES = (
    "tests/live/test_secrets_live.py",
    "tests/integration/test_secret_files_startup.py",
    "tests/unit/core/test_config_secret_files.py",
    "tests/unit/core/test_secret_files.py",
    "tests/unit/core/test_settings_errors.py",
    "tests/unit/test_compose_secrets.py",
    "tests/unit/test_live_cleanup_make.py",
    "tests/unit/test_live_env_guard.py",
    "tests/unit/test_live_isolation_make.py",
    "tests/unit/test_live_session.py",
    "tests/unit/test_make_secrets.py",
    "tests/unit/test_migration_env.py",
    "tests/unit/test_secret_files_cli.py",
)
# Live 的測試只要讀拋棄式的秘密（canary），就必須在上面的清單。
DISPOSABLE_SECRETS = "SECSCAN_LIVE_SECRETS_DIR"


def _docstring(relative: str) -> str:
    tree = ast.parse((ROOT / relative).read_text(encoding="utf-8"))
    return ast.get_docstring(tree) or ""


def test_secret_handling_modules_do_not_rewrite_asserts() -> None:
    missing = [path for path in SECRET_HANDLING_MODULES if MARKER not in _docstring(path)]

    assert missing == []


def test_every_live_module_reading_the_disposable_secrets_is_covered() -> None:
    readers = {
        str(path.relative_to(ROOT))
        for path in (ROOT / "tests" / "live").glob("test_*.py")
        if DISPOSABLE_SECRETS in path.read_text(encoding="utf-8")
    }

    assert readers
    assert readers <= set(SECRET_HANDLING_MODULES), sorted(readers - set(SECRET_HANDLING_MODULES))


def test_this_module_keeps_assertion_rewriting() -> None:
    """正向對照：這個模組自己的 assert 有被改寫（失敗時看得到運算元；它不處理秘密）。

    以行為確認（第二輪程式碼 LOW-2）：loader 不論有沒有標記都是 AssertionRewritingHook，只有實際
    失敗的 assert 帶著運算元的訊息，才證明改寫生效。
    """
    observed = 1
    with pytest.raises(AssertionError) as caught:
        assert observed == EXPECTED_BY_THE_CONTROL
    assert MARKER not in (__doc__ or "")
    assert "1 == 2" in str(caught.value)
