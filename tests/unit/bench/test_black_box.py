"""benchmarks 是黑箱（BENCH-11；docs/DECISIONS.md §29）：只吃 API 的 JSON 與本機的實驗檔案。

- 不 import secscan、tests，也不 import DB、Web 框架、Docker、網路或子程序的模組：平台的內部
  狀態只能經 API 取得，評估不可能讀到 API 沒有公開的值。
- 純函式的模組（評估、統計、比對、正規化、排程、規格）連檔案系統也不碰（除了規格與 ground truth
  的載入函式），只有 results 與 cli 讀寫結果目錄。
"""

import ast
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3] / "benchmarks"
THIRD_PARTY = {"pydantic", "yaml"}
# 只有 sealing 可以使用 cryptography（結果目錄的加密，T23a；docs/DECISIONS.md §30.7）。
CRYPTOGRAPHY_MODULES = {"sealing"}
FORBIDDEN_STDLIB = {
    "socket",
    "ssl",
    "http",
    "urllib",
    "subprocess",
    "multiprocessing",
    "ctypes",
    "pickle",
    "shelve",
    "marshal",
    "importlib",
    "random",
    "asyncio",
}
# 純的模組：只能用標準函式庫中不碰 I/O 的部分（spec 與 ground_truth 的載入函式以 Path 讀檔）。
PURE = {
    "evaluate",
    "stats",
    "matching",
    "metrics",
    "rescan",
    "scoring",
    "collect",
    "schedule",
    "models",
    "manifest",
}
PURE_FORBIDDEN = {"os", "shutil", "tempfile", "io", "pathlib", "glob"}


def _modules() -> list[Path]:
    return sorted(ROOT.glob("*.py"))


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                raise AssertionError(f"{path.name} 不要用相對 import")
            names.add(node.module or "")
        elif isinstance(node, ast.Call) and getattr(node.func, "id", None) in {
            "__import__",
            "eval",
            "exec",
        }:
            raise AssertionError(f"{path.name} 不能動態 import 或執行程式")
    return names


def test_only_sealing_uses_cryptography() -> None:
    users = {
        path.stem
        for path in _modules()
        if any(name.split(".")[0] == "cryptography" for name in _imports(path))
    }
    assert users == CRYPTOGRAPHY_MODULES


def test_there_are_modules_to_check() -> None:
    assert {path.stem for path in _modules()} >= {"spec", "schedule", "collect", "results"}


@pytest.mark.parametrize("path", _modules(), ids=lambda path: path.name)
def test_benchmarks_only_import_the_standard_library_pydantic_yaml_and_itself(path: Path) -> None:
    for name in _imports(path):
        top = name.split(".")[0]
        assert top not in FORBIDDEN_STDLIB, f"{path.name} 不能 import {name}"
        allowed = THIRD_PARTY | ({"cryptography"} if path.stem in CRYPTOGRAPHY_MODULES else set())
        assert top == "benchmarks" or top in allowed or top in sys.stdlib_module_names, (
            f"{path.name} 不能 import {name}"
        )


@pytest.mark.parametrize(
    "path", [p for p in _modules() if p.stem in PURE], ids=lambda path: path.name
)
def test_pure_modules_do_not_touch_files(path: Path) -> None:
    for name in _imports(path):
        assert name.split(".")[0] not in PURE_FORBIDDEN, f"{path.name} 不能 import {name}"
