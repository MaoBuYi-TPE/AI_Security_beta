"""報告 worker 的記錄只留例外的類別與位置（內容可能含不可信的資料）。"""

from secscan.worker.reports import _origin


def test_origin_is_the_last_frame_or_a_placeholder() -> None:
    assert _origin(RuntimeError("never raised")) == "-"
    try:
        raise RuntimeError("payload <script>")
    except RuntimeError as exc:
        origin = _origin(exc)
    assert origin.startswith("test_reports.py:")
    assert "payload" not in origin
