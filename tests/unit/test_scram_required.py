"""CSEC-08：連線一律要求 SCRAM（T23b-b2；計畫 §2.6、§12.8 修正 8）。靜態檢查，不連 DB。

- src/ 中只有 core/db.py（應用程式與 migration）與 cli/db_roles.py（superuser 的移轉）建立連線，
  兩者都帶 require_auth=scram-sha-256；常數只有一份（core/db.py 的 REQUIRE_AUTH）。
- 整合測試的 superuser 連線（database.py、role_support.py）也帶 require_auth。其他四處測試自己建立
  的連線（test_timezone、test_migration_roles 兩處、test_db_privileges）不在範圍內：它們連的是
  db-test 上的測試角色，認證方式由 db-test 的 pg_hba（scram-sha-256）決定。
- 容器內的 libpq：Dockerfile 在建立映像時斷言 libpq ≥ 16（require_auth 需要）。實際執行在 G3 的
  build；這裡只檢查位置與形式。
"""

import ast
import json
from pathlib import Path

from pydantic import SecretStr

from secscan.core.db import REQUIRE_AUTH
from tests.integration.database import IntegrationDbSettings

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src" / "secscan"
CONNECTING_MODULES = frozenset({"core/db.py", "cli/db_roles.py"})


def _calls(path: Path) -> set[str]:
    """這個檔案呼叫的 create_engine 與 psycopg.connect（含 psycopg.Connection.connect）。"""
    found: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name) and func.id == "create_engine":
            found.add("create_engine")
        elif isinstance(func, ast.Attribute) and func.attr in {"create_engine", "connect"}:
            owner = ast.unparse(func.value)
            if func.attr == "create_engine" or owner in {"psycopg", "psycopg.Connection"}:
                found.add(f"{owner}.{func.attr}")
    return found


def test_only_two_modules_open_database_connections() -> None:
    connecting = {path.relative_to(SRC).as_posix() for path in SRC.rglob("*.py") if _calls(path)}

    assert connecting == CONNECTING_MODULES


def test_require_auth_has_a_single_definition() -> None:
    definitions = set()
    for path in SRC.rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Assign):
                names = {ast.unparse(target) for target in node.targets}
                if names & {"REQUIRE_AUTH", "REQUIRE_SCRAM"}:
                    definitions.add(path.relative_to(SRC).as_posix())
    db_roles = (SRC / "cli" / "db_roles.py").read_text(encoding="utf-8")

    assert definitions == {"core/db.py"}
    assert REQUIRE_AUTH == "scram-sha-256"
    assert "from secscan.core.db import" in db_roles
    assert '"require_auth": REQUIRE_AUTH' in db_roles


def test_the_integration_superuser_connections_require_scram() -> None:
    settings = IntegrationDbSettings(password=SecretStr("unused"), _env_file=None)
    role_support = (ROOT / "tests" / "integration" / "role_support.py").read_text(encoding="utf-8")

    assert settings.superuser_url().query["require_auth"] == REQUIRE_AUTH
    assert '"require_auth": REQUIRE_AUTH' in role_support


def test_the_image_asserts_libpq_16_as_the_runtime_user() -> None:
    lines = (ROOT / "Dockerfile").read_text(encoding="utf-8").splitlines()
    user = lines.index("USER 10001:10001")
    runs = [index for index, line in enumerate(lines) if "psycopg.pq.version()" in line]

    assert len(runs) == 1
    [index] = runs
    assert index > user
    line = lines[index]
    assert line.startswith("RUN [")
    argv = json.loads(line.removeprefix("RUN "))
    assert argv[:2] == ["/opt/venv/bin/python", "-c"]
    assert "psycopg.pq.version() >= 160000" in argv[2]
    assert "sys.exit(" in argv[2]
