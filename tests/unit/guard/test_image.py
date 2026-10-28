"""guard 映像的內容（docs/DECISIONS.md §15.1、§15.9）。

guard 在官方 mitmproxy 映像中執行，映像內只有 Dockerfile COPY 進去的模組：
- 以 `python -I`（和映像的 ENTRYPOINT 一樣）載入 run_guard.py 引用的 secscan 模組，載入的模組只能是
  標準函式庫與 secscan；
- secscan 的部分必須正好等於 COPY 清單（少了會在映像中 ImportError，多了是不必要的程式）。
"""

import ast
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
DOCKERFILE = ROOT / "deploy" / "guard" / "Dockerfile"
BOOTSTRAP = ROOT / "deploy" / "guard" / "run_guard.py"
_COPY = re.compile(r"^COPY\s+(?:--\S+\s+)*src/(secscan/\S+\.py)\s+/opt/secscan-guard/(\S+)$")


def _entry_modules() -> list[str]:
    tree = ast.parse(BOOTSTRAP.read_text(encoding="utf-8"))
    return sorted(
        {
            node.module
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
            and node.module
            and node.module.startswith("secscan")
        }
    )


def _loaded_modules(entries: list[str]) -> list[str]:
    script = (
        "import json, sys\n"
        f"sys.path.insert(0, {str(ROOT / 'src')!r})\n"
        f"for name in {entries!r}:\n"
        "    __import__(name)\n"
        "print(json.dumps(sorted(sys.modules)))\n"
    )
    result = subprocess.run(  # noqa: S603 - 固定的直譯器與腳本
        [sys.executable, "-I", "-W", "error", "-c", script],
        capture_output=True,
        text=True,
        check=True,
        timeout=60,
    )
    loaded: list[str] = json.loads(result.stdout)
    return loaded


def _copied() -> set[str]:
    copied: set[str] = set()
    for line in DOCKERFILE.read_text(encoding="utf-8").splitlines():
        match = _COPY.match(line.strip())
        if match is None:
            continue
        source, target = match.groups()
        assert source == target, "COPY 的來源與目的必須是同一個相對路徑"
        copied.add(source.removesuffix(".py").removesuffix("/__init__").replace("/", "."))
    return copied


def test_the_entry_point_only_uses_the_guard_package() -> None:
    entries = _entry_modules()

    assert entries
    assert all(name.startswith("secscan.guard.") for name in entries)


def test_guard_loads_only_the_standard_library_and_secscan() -> None:
    loaded = _loaded_modules(_entry_modules())

    foreign = {
        name
        for name in loaded
        if name.split(".")[0] not in sys.stdlib_module_names
        and name.split(".")[0] not in {"secscan", "__main__"}
        and name not in sys.builtin_module_names
    }
    assert foreign == set()


def test_the_image_copies_exactly_the_modules_the_guard_loads() -> None:
    loaded = {name for name in _loaded_modules(_entry_modules()) if name.startswith("secscan")}

    assert _copied() == loaded


def test_the_image_is_pinned_and_runs_the_bootstrap_as_non_root() -> None:
    lines = [line.strip() for line in DOCKERFILE.read_text(encoding="utf-8").splitlines()]

    [base] = [line for line in lines if line.startswith("FROM ")]
    assert re.fullmatch(r"FROM mitmproxy/mitmproxy:12\.2\.3@sha256:[0-9a-f]{64}", base)
    assert "COPY deploy/guard/run_guard.py /opt/secscan-guard/run_guard.py" in lines
    assert "USER 10001:10001" in lines
    assert lines[-1] == 'ENTRYPOINT ["python3", "-I", "-B", "/opt/secscan-guard/run_guard.py"]'
    assert not any(line.startswith(("RUN pip", "RUN apt", "ADD ")) for line in lines)
