"""held/ 只有一個可信的寫入者，程式不建立 hard link（EVID-10；docs/DECISIONS.md §30.13）。

- 「held/ 不被覆寫」的保證依賴只有 runner 寫 held/：只有列出的模組提到 held 區域
  （Area.HELD、HELD_AREA、held_dir），或逐一走訪所有區域（for … in Area：vault 的寫入檢查、換版；
  程式碼審查 L4）。
- 跨掛載點的 link(2) 會得到 EXDEV；程式本身也不使用 os.link。
"""

import ast
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[3] / "src" / "secscan"
# runner 程序與 runner 容器內的管理指令（retry-evidence、migrate-runs-layout、
# rotate-evidence-keys）。
HELD_WRITERS = {
    "runner/domain/areas.py",
    "runner/layout.py",
    "runner/hold_moves.py",
    "runner/isolation.py",
    "runner/layout_migration.py",
    "runner/sealed_files.py",
    "cli/evidence_holds.py",
    # 以 for … in Area 走訪兩個區域：都在 runner 程序或 runner 容器內執行。
    "runner/evidence.py",
    "cli/evidence.py",
    # worker 啟動時確認自己看不到 held/（只 lstat，不寫入）。
    "cli/services.py",
}
_HELD_NAMES = {"HELD", "HELD_AREA", "held_dir"}


def _modules() -> list[tuple[str, ast.AST]]:
    return [
        (str(path.relative_to(SOURCE)), ast.parse(path.read_text(encoding="utf-8")))
        for path in sorted(SOURCE.rglob("*.py"))
    ]


def _mentions_held(tree: ast.AST) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, (ast.For, ast.comprehension)) and _is_area(node.iter):
            return True
        if isinstance(node, ast.Attribute) and node.attr in _HELD_NAMES:
            return True
        if isinstance(node, ast.Name) and node.id in _HELD_NAMES:
            return True
        if isinstance(node, ast.alias) and node.name in _HELD_NAMES:
            return True
    return False


def _is_area(node: ast.AST) -> bool:
    return isinstance(node, ast.Name) and node.id == "Area"


def test_only_the_runner_modules_refer_to_held() -> None:
    found = {name for name, tree in _modules() if _mentions_held(tree)}

    assert found == HELD_WRITERS


def _links(node: ast.AST) -> bool:
    if not isinstance(node, ast.Attribute):
        return False
    if node.attr in {"hardlink_to", "link_to"}:
        return True
    return node.attr == "link" and isinstance(node.value, ast.Name) and node.value.id == "os"


def test_no_module_creates_hard_links() -> None:
    linking = {name for name, tree in _modules() for node in ast.walk(tree) if _links(node)}
    imported = {
        name
        for name, tree in _modules()
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
        and node.module == "os"
        and any(alias.name == "link" for alias in node.names)
    }

    assert linking == set()
    assert imported == set()
