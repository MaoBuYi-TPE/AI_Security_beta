"""以 AST 檢查 src 的呼叫者：只能由特定模組呼叫的函式（例如 issue_admin_key、reveal）。"""

import ast
from pathlib import Path

import secscan

SOURCE_ROOT = Path(secscan.__file__).resolve().parent


def modules_using(attribute: str) -> set[str]:
    """src 中以屬性形式用到 attribute（例如 `x.reveal(...)`）的模組，以相對路徑表示。"""
    users: set[str] = set()
    for path in SOURCE_ROOT.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        if any(
            isinstance(node, ast.Attribute) and node.attr == attribute for node in ast.walk(tree)
        ):
            users.add(path.relative_to(SOURCE_ROOT).as_posix())
    return users
