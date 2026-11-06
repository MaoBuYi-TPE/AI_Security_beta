"""成功、逾時與可解釋的 Nuclei 部分失敗仍須和 scan 完整度一致。"""

from collections.abc import Mapping
from typing import Any


def assert_engine_outcome(engine: Mapping[str, Any], scan: Mapping[str, Any]) -> None:
    result = engine["result"]
    assert isinstance(result, Mapping), "缺少引擎解析結果"
    errors = result["engine_errors"]
    assert type(errors) is int, "引擎錯誤數無效"
    assert errors >= 0, "引擎錯誤數無效"
    status, code = engine["status"], engine["error_code"]
    if status == "succeeded":
        assert code is None, "成功狀態不能隱藏錯誤碼"
        assert errors == 0, "成功狀態不能隱藏引擎錯誤"
        return
    assert scan["results_complete"] is False, "引擎未完成卻回報完整 scan"
    if status == "timed_out":
        return
    assert engine["engine"] == "nuclei", "不接受 ZAP 或其他引擎的失敗"
    assert status == "failed", "不接受取消或中斷"
    assert code == "ENGINE_REPORTED_ERRORS", "只接受 Nuclei 模板部分失敗"
    assert errors > 0, "Nuclei 模板失敗必須有錯誤計數"
