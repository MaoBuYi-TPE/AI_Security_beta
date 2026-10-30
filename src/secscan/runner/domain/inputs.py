"""輸入檔的內容規則（docs/DECISIONS.md §18.4；T14 的審查 M1）。

ZAP 的 AF plan 是 ZAP 要執行的程式，而且 ZAP 的環境中有注入的認證值：AF 會把 ${名稱} 代換成環境
變數。builder 已經拒絕 ${，這裡是獨立的第二道檢查（不引用 builder 的常數）：之後有人改了 builder，
admission 仍然擋得住。檔案以 JSON 解析（builder 輸出的 JSON 也是合法的 YAML）。
"""

import hashlib
import json
from dataclasses import dataclass

_VARIABLE = "${"


@dataclass(frozen=True, slots=True)
class ContentDigest:
    """內容固定的輸入檔（probe 的 plan）：sha256 必須相同。"""

    sha256: str

    def accepts(self, content: bytes) -> bool:
        return hashlib.sha256(content).hexdigest() == self.sha256


@dataclass(frozen=True, slots=True)
class AutomationPlan:
    """AF plan 的白名單：job 的類型、唯一的報告（範本與目錄）、active scan 只跑列出的規則。"""

    job_types: frozenset[str]
    report_template: str
    report_dir: str

    def accepts(self, content: bytes) -> bool:
        if _VARIABLE.encode() in content:
            return False
        try:
            document = json.loads(content)
            disguised = _has_variable(document)
        except (UnicodeDecodeError, ValueError, RecursionError):
            # ValueError 也包含超過位數上限的整數（不是 JSONDecodeError）；走訪的深度和解析相同，
            # 也可能遞迴過深。
            return False
        if disguised or not isinstance(document, dict):
            return False
        jobs = document.get("jobs")
        if not isinstance(jobs, list) or not all(isinstance(job, dict) for job in jobs):
            return False
        if not all(job.get("type") in self.job_types for job in jobs):
            return False
        reports = [job for job in jobs if job["type"] == "report"]
        return (
            len(reports) == 1
            and self._report_allowed(reports[0])
            and all(_only_listed_rules(job) for job in jobs if job["type"] == "activeScan")
        )

    def _report_allowed(self, job: dict[str, object]) -> bool:
        parameters = job.get("parameters")
        return (
            isinstance(parameters, dict)
            and parameters.get("template") == self.report_template
            and parameters.get("reportDir") == self.report_dir
        )


def _only_listed_rules(job: dict[str, object]) -> bool:
    definition = job.get("policyDefinition")
    return isinstance(definition, dict) and definition.get("defaultThreshold") == "off"


def _has_variable(value: object) -> bool:
    """解析之後再找一次：JSON 的 \\u0024 跳脫在檔案中看不到 ${。"""
    if isinstance(value, str):
        return _VARIABLE in value
    if isinstance(value, dict):
        return any(_has_variable(key) or _has_variable(child) for key, child in value.items())
    if isinstance(value, list):
        return any(_has_variable(child) for child in value)
    return False
