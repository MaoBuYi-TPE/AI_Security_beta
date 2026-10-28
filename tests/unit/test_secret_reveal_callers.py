"""只有 runner 解密目標的 secret（docs/DECISIONS.md §12.2、§14.5）。

API 只加密：新版本沿用 secret 時直接複製密文，金鑰換版用 rotate（不回傳明文）。runner 在建立
掃描容器之前才解密，寫成 0400 的檔案注入（runner/service.py），是唯一的呼叫者。
"""

from tests.unit.source_support import modules_using


def test_only_the_container_runner_reveals_target_secrets() -> None:
    assert modules_using("reveal") == {"runner/service.py"}


def test_only_the_local_cli_reencrypts_secrets() -> None:
    """reencrypt_secrets 沒有呼叫者身分可以檢查（同 issue_admin_key）：只有本機 CLI 呼叫它。"""
    assert modules_using("reencrypt_secrets") == {"cli/__init__.py"}
