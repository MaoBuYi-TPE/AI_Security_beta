"""報告中平台自己的所有文字（Gate D：報告無未驗證的誇大敘述；docs/DECISIONS.md §28.1、§28.5）。

- 固定說明：未經 triage 的告警不是已驗證的漏洞；零告警不代表沒有弱點；not_observed 不等於已修補；
  報告產生時間不是發現或修補時間；平台不提供自動修補驗證；遮罩不保證辨識所有秘密。
- resolved 一律寫成「標記為 resolved（人工判定）」並附依據；需要人工確認的另外標示，不算已修補。
- claims_violations：平台文字中出現「已修補、fixed、verified…」這類字詞時，只允許出現在白名單中的
  否定說明裡。測試以它檢查這裡的所有常數與渲染結果中 code 以外的文字。
"""

import re

from secscan.findings.domain.triage import ResolutionBasis

NOTICES = (
    "本報告由平台產生；未經人工 triage 的告警只是工具告警，不是已驗證的漏洞。",
    "零告警不代表沒有弱點：掃描只涵蓋實際送出的請求與啟用的規則。",
    "複掃比較的 not_observed 不等於已修補；inconclusive 代表平台無法判斷。",
    "本平台不提供自動修補驗證：resolved 一律是人工判定；人工複測證據由操作者提供，"
    "平台只做一致性檢查，未驗證其真實性。",
    "報告的產生時間與資料時間不是發現或修補的時間。",
    "遮罩依名稱與樣式判斷，不保證辨識所有秘密；分享報告前請自行檢查。",
)
FIXTURE_NOTICE = "這是 fixture 測試資料的掃描結果，不代表真實系統。"
INCOMPLETE_NOTICE = "掃描未完整完成（狀態：{status}）：結果不完整，未觀察到的項目不能視為不存在。"
TRUNCATED_NOTICE = (
    "報告超過大小上限，已依優先順序省略 {omitted} 個 finding；摘要的計數仍以全部 finding 計算。"
)
COMPARISON_NOTICE = "比較快照是平台事實，不等於已修補；人工判定的 resolved 不會修改它。"
UNTRUSTED_NOTICE = "以程式碼格式顯示的內容來自工具輸出或人工輸入，是不可信的資料。"

TRIAGE_LABELS = {
    "unreviewed": "未確認：工具告警，不是已驗證的漏洞",
    "confirmed": "人工確認（操作者判斷）",
    "false_positive": "人工判定誤報",
    "accepted_risk": "風險接受（未修補）",
}
LIFECYCLE_LABELS = {
    "open": "未處理",
    "reopened": "重新開啟（曾標記為 resolved 之後又觀察到）",
    "resolved": "標記為 resolved（人工判定）",
}
BASIS_LABELS = {
    ResolutionBasis.RESCAN_NOT_OBSERVED.value: (
        "依據：平台複掃未觀察到，三層覆蓋皆成立；未觀察到不等於已修補"
    ),
    ResolutionBasis.MANUAL_RETEST.value: ("依據：操作者提供的人工複測證據，平台只做一致性檢查"),
}
REVIEW_LABEL = "resolved 之後又被觀察到或規則已換版，需要人工確認；不計入 resolved"
MULTIPLE_SOURCES_LABEL = "多個來源只代表多個工具告警，不等於人工確認"
SECTION_TITLES = {
    "report": "掃描報告",
    "notices": "固定說明",
    "scan": "掃描",
    "authorization": "授權",
    "engines": "引擎",
    "coverage": "覆蓋",
    "summary": "摘要",
    "findings": "Finding",
    "comparisons": "比較快照",
    "truncation": "截斷",
}
FIELD_LABELS = {
    "approved_at": "授權成立時間",
    "data_as_of": "資料時間",
    "generated_at": "報告產生時間",
}

# 「誇大的字詞」只允許出現在這些否定說明中。
_FORBIDDEN = re.compile(
    r"已修補|已修復|無弱點|安全無虞|已驗證的漏洞|自動驗證|平台已驗證|已確認修補"
    r"|\bfixed\b|\bsecure\b|\bverified\b|\bauto-verified\b",
    re.IGNORECASE,
)
_NEGATIONS = (
    "不是已驗證的漏洞",
    "不等於已修補",
    "不提供自動修補驗證",
    "未驗證其真實性",
    "不計入 resolved",
)


def claims_violations(text: str) -> list[str]:
    """平台文字中不在否定說明裡的誇大字詞（空的代表沒有違規）。"""
    remaining = text
    for negation in _NEGATIONS:
        remaining = remaining.replace(negation, " ")
    return [match.group(0) for match in _FORBIDDEN.finditer(remaining)]


def all_platform_text() -> tuple[str, ...]:
    return (
        *NOTICES,
        FIXTURE_NOTICE,
        INCOMPLETE_NOTICE,
        TRUNCATED_NOTICE,
        COMPARISON_NOTICE,
        UNTRUSTED_NOTICE,
        *TRIAGE_LABELS.values(),
        *LIFECYCLE_LABELS.values(),
        *BASIS_LABELS.values(),
        REVIEW_LABEL,
        MULTIPLE_SOURCES_LABEL,
        *SECTION_TITLES.values(),
        *FIELD_LABELS.values(),
    )
