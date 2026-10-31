"""AF 的結尾摘要（docs/DECISIONS.md §19.2）：判斷退出碼 1、2 的語意需要它。

ExtensionAutomation 在最後一個 job 之後輸出：沒有錯誤與警告時一行 `Automation plan succeeded!`；
否則 `Automation plan failures:`、`Automation plan warnings:`（依序、各一次），之後每個訊息一行，
以 tab 開頭。訊息本身可以有換行。只判讀最後一行 `Job ` 開頭的進度之後的內容，整行比對；訊息的文字
可能含 URL 或目標的內容，只計數，不保存。順序不符合這個格式就不判讀（None）。
"""

import re
from dataclasses import dataclass

_SUCCEEDED = "Automation plan succeeded!"
_FAILURES = "Automation plan failures:"
_WARNINGS = "Automation plan warnings:"
_JOB_LINE = "Job "
_MESSAGE = "\t"
# plan 的 env.parameters.maxDuration（automation 0.61.0 的 Messages.properties；實測）。
_MAX_DURATION = re.compile(r"\tPlan stopped after reaching maximum duration of [0-9]+ second\(s\)")


@dataclass(frozen=True, slots=True)
class PlanSummary:
    succeeded: bool = False
    errors: int = 0
    warnings: int = 0
    max_duration: bool = False


def parse_summary(log: bytes) -> PlanSummary | None:
    lines = log.decode("utf-8", errors="replace").split("\n")
    last_job = max(
        (index for index, line in enumerate(lines) if line.startswith(_JOB_LINE)), default=-1
    )
    if last_job < 0:
        return None
    tail = lines[last_job + 1 :]
    headers = [
        (index, line)
        for index, line in enumerate(tail)
        if line in {_SUCCEEDED, _FAILURES, _WARNINGS}
    ]
    titles = [line for _, line in headers]
    if titles == [_SUCCEEDED]:
        return _succeeded(tail)
    if titles not in ([_FAILURES], [_WARNINGS], [_FAILURES, _WARNINGS]):
        return None
    return _counted(tail, headers)


def _succeeded(tail: list[str]) -> PlanSummary | None:
    if any(line.startswith(_MESSAGE) for line in tail):
        return None
    return PlanSummary(succeeded=True)


def _counted(tail: list[str], headers: list[tuple[int, str]]) -> PlanSummary | None:
    ends = [index for index, _ in headers[1:]] + [len(tail)]
    errors = warnings = 0
    max_duration = False
    for (start, title), end in zip(headers, ends, strict=True):
        messages = [line for line in tail[start + 1 : end] if line.startswith(_MESSAGE)]
        if not messages:
            return None
        if title == _FAILURES:
            errors = len(messages)
        else:
            warnings = len(messages)
            max_duration = any(_MAX_DURATION.fullmatch(line) is not None for line in messages)
    return PlanSummary(errors=errors, warnings=warnings, max_duration=max_duration)
