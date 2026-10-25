"""只有本機 CLI 可以建立 platform_admin key（docs/DECISIONS.md §9.1）。

ApiKeyService.issue_admin_key 不做授權檢查（CLI 沒有呼叫者身分可以檢查）。如果日後有路由誤用它，
任何持有 key 的人都能建立 admin key，所以這裡檢查 src 中只有 secscan/cli.py 呼叫它。
"""

from tests.unit.source_support import modules_using


def test_only_the_local_cli_issues_admin_keys() -> None:
    assert modules_using("issue_admin_key") == {"cli.py"}
