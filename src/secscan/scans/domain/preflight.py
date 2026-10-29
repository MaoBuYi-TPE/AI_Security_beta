"""preflight 的結果（docs/DECISIONS.md §16.5）。worker 判斷之後寫進 preflight 的 run。"""

from enum import StrEnum


class PreflightResult(StrEnum):
    # 帶認證的回應符合 §12.5 的比對，匿名的不符合。
    PASSED = "passed"
    # 帶認證的回應不符合（狀態碼、不是 JSON 或內容不同）。
    FAILED = "failed"
    # 匿名的回應也符合：端點沒有受保護，證明不了認證有效。
    INCONCLUSIVE = "inconclusive"
    # guard 拒絕了 preflight 的請求（不在範圍內、預算用盡等）。
    BLOCKED = "blocked"
    # 沒有可用的回應（容器失敗、連不上、輸出不是 HTTP 回應）。
    NOT_EXECUTED = "not_executed"
