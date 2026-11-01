"""T17：凍結模板清單的重現性（gated live；ENABLE_LIVE_LAB_TESTS=1、make nuclei-templates-check）。

重新驗證鎖定的 archive（sha256）、乾淨解壓、在鎖定的 nuclei 映像裡離線跑 nuclei -tl，確認重新產生的
lock 與已提交的逐位元組一致（含每個模板的 sha256）。需要 docker 與鎖定的 nuclei 映像，不連任何目標、
不出網（--network none）。make test 不跑（tests/isolation.py 在沒有開關時於收集階段 skip）。
"""

import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = [pytest.mark.live, pytest.mark.enable_socket]

_ROOT = Path(__file__).resolve().parents[2]
_GENERATOR = _ROOT / "tools" / "freeze_nuclei_templates.py"


def test_frozen_lock_reproduces_from_pinned_release() -> None:
    # 產生器的 --check：重跑列舉並和已提交的 lock 比對，不同就以非零退出。
    result = subprocess.run(  # noqa: S603
        [sys.executable, str(_GENERATOR), "--check"],
        cwd=_ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=600,
    )
    assert result.returncode == 0, result.stdout + result.stderr
