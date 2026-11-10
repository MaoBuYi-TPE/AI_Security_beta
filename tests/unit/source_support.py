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


def modules_calling(name: str) -> set[str]:
    """src 中以名稱呼叫 name（例如 `evidence_cipher(...)`）或以屬性存取它的模組。"""
    users: set[str] = set()
    for path in SOURCE_ROOT.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            called = isinstance(node, ast.Call) and (
                (isinstance(node.func, ast.Name) and node.func.id == name)
                or (isinstance(node.func, ast.Attribute) and node.func.attr == name)
            )
            if called:
                users.add(path.relative_to(SOURCE_ROOT).as_posix())
                break
    return users
