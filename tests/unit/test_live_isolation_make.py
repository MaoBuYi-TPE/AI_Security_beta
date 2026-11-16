"""惡意環境下的 Live 隔離（CSEC-12、CSEC-13；T23b-b2，計畫 §3.1、§3.1.1；§12.8 修正 1、2、5、6）。

(a) 以 repo 的 Makefile 在 pytest 的暫存目錄實際執行 make test-live-runner：docker 與 uv 換成放在
    PATH 最前面的假執行檔，記下每次呼叫的 argv 與完整的環境。shell 的環境是惡意的：七個秘密、
    *_FILE、PGPASSWORD、PGPASSFILE、SECSCAN_SECRETS_DIR、COMPOSE_ENV_FILES、COMPOSE_FILE、
    COMPOSE_PROJECT_NAME、SECSCAN_LIVE_PROJECT=secscan 都指向 canary；暫存目錄另有 canary 的 .env
    與 compose.override.yaml。假的 uv 對 generate-secret-files 與 env_guard 執行真的程式；假的
    docker 把 `compose config` 交給真的 docker compose（只在用戶端解析，DOCKER_HOST 指向不存在的
    socket）。
(b) 正向對照：同樣的惡意環境、不經包裝時，canary 確實會被 compose 載入（測試不會空轉）。
(d) 靜態：Live 的每一個呼叫都經過白名單。

這些都不連 Docker daemon、不建立任何容器；實際的 Live 隔離在 G3 驗證（CSEC-L5）。
"""

import ast
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from secscan.cli.secret_files import SECRET_FILES
from tests.isolation import BLOCKED_DOCKER_HOST

ROOT = Path(__file__).resolve().parents[2]
MAKEFILE_PATH = ROOT / "Makefile"
MAKEFILE = MAKEFILE_PATH.read_text(encoding="utf-8")
SECRET_NAMES = frozenset(
    {
        *(item.env_name for item in SECRET_FILES),
        *(f"{item.env_name}_FILE" for item in SECRET_FILES),
        "POSTGRES_PASSWORD",
        "PGPASSWORD",
        "SECSCAN_OWNER_DB_PASSWORD",
        "SECSCAN_APP_DB_PASSWORD",
    }
)
BASE_NAMES = {"PATH", "HOME", "TMPDIR", "LC_ALL", "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG"}
PASS_NAMES = {
    "SECSCAN_RECORD_DIR",
    "SECSCAN_PARTIAL_BUDGET_SECONDS",
    "BENCH_SPEC",
    "BENCH_NAME",
    "BENCH_KEY_FILE",
}
FIXED = {
    "SECSCAN_IMAGE_TAG": "dev",
    "COMPOSE_DISABLE_ENV_FILE": "1",
    "PGPASSFILE": "/dev/null",
    "SECSCAN_LIVE_PROJECT": "secscan-live",
    "ENABLE_LIVE_LAB_TESTS": "1",
}
ALEMBIC_FILES = {
    "DB_PASSWORD_FILE": "db_password",
    "DB_OWNER_PASSWORD_FILE": "db_owner_password",
    "SECRET_ENCRYPTION_KEYS_FILE": "secret_encryption_keys",
    "EVIDENCE_ENCRYPTION_KEYS_FILE": "evidence_encryption_keys",
    "CONTENT_ENCRYPTION_KEYS_FILE": "content_encryption_keys",
}
PLACEHOLDER = "/nonexistent/secscan-live-secrets.unset"
# 子 make（ensure-net）自己加上的變數：命令列的 NET、SUBNET、IP_RANGE 與 Makefile export 的 BENCH_*
# （白名單之下是空值或 LIVE_PASS_ENV 的值）。只允許出現在子 make 內的呼叫（環境有 MAKELEVEL）。
SUBMAKE = {
    "NET",
    "SUBNET",
    "IP_RANGE",
    "MAKEOVERRIDES",
    "BENCH_TRUTH",
    "BENCH_ADJUDICATIONS",
    "BENCH_PAIR_LABELS",
    "BENCH_INCLUDE_HOLDOUT",
    "BENCH_SOURCE",
}
# 程序本身加上的變數（make、shell）：不是從 shell 帶進來的設定。
PLUMBING = {
    "MAKEFLAGS",
    "MAKELEVEL",
    "MFLAGS",
    "PWD",
    "OLDPWD",
    "SHLVL",
    "_",
    "__CF_USER_TEXT_ENCODING",
}


def _live_env_names() -> set[str]:
    match = re.search(r"^LIVE_ENV := ((?:.*\\\n)*.*)$", MAKEFILE, flags=re.MULTILINE)
    assert match is not None
    return {item.split("=", 1)[0] for item in match.group(1).replace("\\\n", " ").split()}


ALLOWED = (
    BASE_NAMES
    | PASS_NAMES
    | _live_env_names()
    | set(FIXED)
    | {
        "SECSCAN_SECRETS_DIR",
        "SECSCAN_LIVE_SECRETS_DIR",
    }
)

_FAKE_DOCKER = """#!{python}
import json, os, subprocess, sys
args = sys.argv[1:]
with open({log!r}, "a") as log:
    log.write(json.dumps({{"tool": "docker", "argv": args, "env": dict(os.environ)}}) + "\\n")
scenario = json.loads(open({scenario!r}).read())
def out(text="", code=0):
    sys.stdout.write(text)
    sys.exit(code)
nets = {{"secscan_live_scan_net": "10.89.9.0/24 10.89.9.0/25",
        "secscan_live_lab_net": "10.89.10.0/24 10.89.10.0/25"}}
if args[:2] == ["context", "show"]:
    out("orbstack\\n")
if args[:1] in (["version"], ["pull"], ["rm"]):
    out()
if args[:1] == ["info"]:
    out("engine-1\\n")
if args[:1] == ["compose"]:
    if "version" in args:
        out("5.1.2\\n")
    if "config" in args:
        result = subprocess.run(
            [{real_docker!r}, *args], capture_output=True, text=True, check=False,
            env={{**os.environ, "DOCKER_HOST": {blocked!r}}},
        )
        name = "environment" if "--environment" in args else (
            "unresolved" if "--no-env-resolution" in args else "resolved")
        with open(os.path.join({records!r}, name), "w") as record:
            record.write(result.stdout)
        sys.stderr.write(result.stderr)
        out(result.stdout, result.returncode)
    if "up" in args:
        if scenario.get("up_fails"):
            out(code=1)
        if "db" not in args:
            open({state!r}, "w").write("up")
        out()
    if "down" in args:
        if os.path.exists({state!r}):
            os.remove({state!r})
        out()
    out()
if args[:1] == ["ps"]:
    live = "label=com.docker.compose.project=secscan-live" in args
    if live and os.path.exists({state!r}):
        out("c-api\\nc-runner\\nc-worker\\nc-guard\\n")
    out()
if args[:1] == ["inspect"]:
    service = args[-1][2:]
    out(service + (" sha256:guard\\n" if service == "guard" else " sha256:app\\n"))
if args[:2] == ["image", "inspect"]:
    out("sha256:guard\\n" if args[-1].startswith("secscan-guard") else "sha256:app\\n")
if args[:2] in (["volume", "ls"], ["network", "ls"], ["network", "rm"], ["network", "create"]):
    out()
if args[:2] == ["network", "inspect"]:
    fmt = args[args.index("--format") + 1] if "--format" in args else ""
    if ".Internal" in fmt:
        out("true\\n")
    if "gateway_mode" in fmt:
        out("isolated\\n")
    if "IPAM" in fmt:
        out(nets[args[2]] + "\\n")
    out("[]")
sys.exit(2)
"""

_FAKE_UV = """#!{python}
import json, os, sys
args = sys.argv[1:]
with open({log!r}, "a") as log:
    log.write(json.dumps({{"tool": "uv", "argv": args, "env": dict(os.environ)}}) + "\\n")
rest = args[2:] if args[:2] == ["run", "--locked"] else sys.exit(3)
if rest[:2] == ["python", "-I"]:
    os.execve({python!r}, [{python!r}, "-I", *rest[2:]], dict(os.environ))
if rest[:1] == ["secscan-admin"]:
    os.execve({admin!r}, [{admin!r}, *rest[1:]], dict(os.environ))
if rest[:1] in (["alembic"], ["pytest"]):
    sys.exit(0)
sys.exit(2)
"""


def _real_docker() -> str:
    cli = shutil.which("docker")
    if cli is None:
        pytest.skip("沒有安裝 docker CLI")
    return cli


class Hostile:
    """暫存的 project directory 與惡意的 shell 環境（值都是 canary）。"""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.project = root / "project"
        self.project.mkdir()
        shutil.copy(ROOT / "compose.yaml", self.project / "compose.yaml")
        self.tmpdir = root / "tmp-base"
        self.tmpdir.mkdir()
        self.bin = root / "bin"
        self.bin.mkdir()
        self.records = root / "records"
        self.records.mkdir()
        self.log = root / "calls.log"
        self.log.write_text("", encoding="utf-8")
        self.state = root / "state"
        self.scenario = root / "scenario.json"
        self.scenario.write_text("{}", encoding="utf-8")
        self.canaries = {name: f"canary-{secrets.token_hex(10)}" for name in sorted(SECRET_NAMES)}
        self.canary_dir = root / "dev-secrets"
        self.canary_dir.mkdir(mode=0o700)
        for item in SECRET_FILES:
            (self.canary_dir / item.file_name).write_text(
                self.canaries[item.env_name], encoding="ascii"
            )
        env_lines = "".join(f"{key}={value}\n" for key, value in self.canaries.items())
        (self.project / ".env").write_text(env_lines, encoding="utf-8")
        self.env_files = root / "extra.env"
        self.env_files.write_text(
            env_lines + f"SECSCAN_SECRETS_DIR={self.canary_dir}\n", encoding="utf-8"
        )
        self.override = self.project / "compose.override.yaml"
        self.override.write_text(
            f"services:\n  api:\n    environment:\n      LEAK: {self.canaries['DB_PASSWORD']}\n",
            encoding="utf-8",
        )
        self.pgpass = root / "pgpass"
        self.pgpass.write_text(f"*:*:*:*:{self.canaries['PGPASSWORD']}\n", encoding="ascii")
        self._install(_real_docker())

    def _install(self, real_docker: str) -> None:
        values = {
            "python": sys.executable,
            "log": str(self.log),
            "scenario": str(self.scenario),
            "state": str(self.state),
            "records": str(self.records),
            "real_docker": real_docker,
            "blocked": BLOCKED_DOCKER_HOST,
            "admin": str(Path(sys.executable).parent / "secscan-admin"),
        }
        for name, template in (("docker", _FAKE_DOCKER), ("uv", _FAKE_UV)):
            script = self.bin / name
            script.write_text(template.format(**values), encoding="utf-8")
            script.chmod(script.stat().st_mode | stat.S_IXUSR)

    def environment(self) -> dict[str, str]:
        return {
            **self.canaries,
            "PATH": f"{self.bin}{os.pathsep}{os.environ.get('PATH', '')}",
            "HOME": str(self.root),
            # 以 / 結尾（G0 的調整 1）：拋棄式目錄的路徑不能有 //。
            "TMPDIR": f"{self.tmpdir}/",
            "LC_ALL": "C.UTF-8",
            "DOCKER_HOST": BLOCKED_DOCKER_HOST,
            # 真的 docker compose plugin 在這裡（只用於 compose config 的用戶端解析）。
            "DOCKER_CONFIG": str(Path.home() / ".docker"),
            "ENABLE_LIVE_LAB_TESTS": "1",
            "SECSCAN_LIVE_PROJECT": "secscan",
            "SECSCAN_SECRETS_DIR": str(self.canary_dir),
            "COMPOSE_ENV_FILES": str(self.env_files),
            "COMPOSE_FILE": str(self.override),
            "COMPOSE_PROJECT_NAME": "secscan",
            "PGPASSFILE": str(self.pgpass),
            "PGHOST": "db.example",
            "LIVE_PROC_ENV": "env",
            "SECSCAN_RECORD_DIR": str(self.root / "recordings"),
        }

    def make(self, *args: str, **extra_env: str) -> subprocess.CompletedProcess[str]:
        make = shutil.which("make")
        assert make is not None, "需要 make"
        # 固定的 make 與 repo 的 Makefile；docker 與 uv 是假的執行檔。
        return subprocess.run(  # noqa: S603
            [
                make,
                "--no-print-directory",
                "-f",
                str(MAKEFILE_PATH),
                "UV_RUN=uv run --locked",
                *args,
                "test-live-runner",
            ],
            cwd=self.project,
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
            env={**self.environment(), **extra_env},
        )

    def calls(self) -> list[dict[str, Any]]:
        lines = self.log.read_text(encoding="utf-8").splitlines()
        return [json.loads(line) for line in lines if line]

    def leaked(self, text: str) -> set[str]:
        """只回傳名稱：失敗時 pytest 不會印出 canary 的值。"""
        found = {name for name, value in self.canaries.items() if value in text}
        if str(self.canary_dir) in text:
            found.add("SECSCAN_SECRETS_DIR")
        return found


@pytest.fixture
def hostile(tmp_path: Path) -> Hostile:
    return Hostile(tmp_path)


def _secrets_dirs(hostile: Hostile) -> list[str]:
    return sorted(name for name in os.listdir(hostile.tmpdir) if name.startswith("secscan-live-"))


def test_every_call_runs_in_the_whitelisted_environment(hostile: Hostile) -> None:
    result = hostile.make()

    assert result.returncode == 0, (
        hostile.leaked(result.stdout + result.stderr) or result.stderr[-2000:]
    )
    calls = hostile.calls()
    assert calls
    pattern = re.compile(
        rf"{re.escape(str(hostile.tmpdir))}/secscan-live-secrets\.[A-Za-z0-9]{{6}}"
    )
    directories = set()
    for call in calls:
        environment = call["env"]
        assert hostile.leaked(json.dumps(call)) == set(), call["argv"][:3]
        extra = SUBMAKE if "MAKELEVEL" in environment else set()
        unexpected = set(environment) - ALLOWED - set(ALEMBIC_FILES) - PLUMBING - extra
        assert unexpected == set(), (call["argv"][:3], sorted(unexpected))
        for key, value in FIXED.items():
            assert environment.get(key) == value, (call["argv"][:3], key)
        directory = environment["SECSCAN_SECRETS_DIR"]
        # mktemp 之前（engine、preflight、snapshot）是不存在的佔位路徑（D16：一律非空）。
        assert directory == PLACEHOLDER or pattern.fullmatch(directory), call["argv"][:3]
        assert environment["SECSCAN_LIVE_SECRETS_DIR"] == directory
        if directory != PLACEHOLDER:
            directories.add(directory)
        if call["argv"][:1] == ["compose"] and "version" not in call["argv"]:
            assert directory != PLACEHOLDER, call["argv"][:3]
    # 每次都是新的拋棄式目錄；結束時已刪除。
    assert len(directories) == 1
    assert _secrets_dirs(hostile) == []


def test_build_pull_network_and_cleanup_calls_are_wrapped_too(hostile: Hostile) -> None:
    """D17：Live 專用的 build、pull、子 make 的網路與清理段都經過白名單。"""
    assert hostile.make().returncode == 0
    argvs = [call["argv"] for call in hostile.calls() if call["tool"] == "docker"]

    assert any(argv[:1] == ["compose"] and "build" in argv for argv in argvs)
    assert any(argv[:1] == ["pull"] for argv in argvs)
    assert any(argv[:2] == ["network", "inspect"] for argv in argvs)
    assert any(argv[:1] == ["compose"] and "down" in argv for argv in argvs)
    for argv in argvs:
        if argv[:1] == ["compose"] and argv[1:2] != ["version"]:
            assert argv[1:5] == ["-p", "secscan-live", "-f", "compose.yaml"], argv
            assert "--env-file" not in argv


def test_alembic_and_pytest_get_only_the_disposable_secrets(hostile: Hostile) -> None:
    assert hostile.make().returncode == 0
    uv_calls = [call for call in hostile.calls() if call["tool"] == "uv"]
    [alembic] = [call for call in uv_calls if call["argv"][2:3] == ["alembic"]]
    [pytest_call] = [call for call in uv_calls if call["argv"][2:3] == ["pytest"]]
    [generate] = [
        call for call in uv_calls if call["argv"][2:4] == ["secscan-admin", "generate-secret-files"]
    ]

    assert alembic["argv"][3:6] == ["-x", "dotenv=off", "upgrade"]
    directory = alembic["env"]["SECSCAN_SECRETS_DIR"]
    for key, name in ALEMBIC_FILES.items():
        assert alembic["env"][key] == f"{directory}/{name}"
    assert generate["argv"][4:] == [directory]
    assert pytest_call["argv"][3:5] == ["-m", "live"]
    assert pytest_call["env"]["SECSCAN_LIVE_PROJECT"] == "secscan-live"
    assert pytest_call["env"]["ENABLE_LIVE_LAB_TESTS"] == "1"
    assert pytest_call["env"]["SECSCAN_RECORD_DIR"] == str(hostile.root / "recordings")
    assert not set(ALEMBIC_FILES) & set(pytest_call["env"])


def test_the_resolved_configuration_uses_only_the_disposable_directory(hostile: Hostile) -> None:
    """(b) 經過包裝：真的 docker compose 解析出來的 secret 都在拋棄式目錄之下，環境沒有 canary。"""
    assert hostile.make().returncode == 0
    resolved = json.loads((hostile.records / "resolved").read_text(encoding="utf-8"))
    environment = (hostile.records / "environment").read_text(encoding="utf-8")
    [directory] = {
        call["env"]["SECSCAN_SECRETS_DIR"]
        for call in hostile.calls()
        if call["tool"] == "docker" and "config" in call["argv"]
    }

    files = {entry["file"] for entry in resolved["secrets"].values()}
    assert {os.path.dirname(os.path.normpath(path)) for path in files} == {directory}
    assert hostile.leaked(json.dumps(resolved)) == set()
    assert hostile.leaked(environment) == set()
    names = {line.split("=", 1)[0] for line in environment.splitlines() if "=" in line}
    assert "COMPOSE_ENV_FILES" not in names
    assert not names & SECRET_NAMES


def test_a_failed_step_still_cleans_up(hostile: Hostile) -> None:
    hostile.scenario.write_text(json.dumps({"up_fails": True}), encoding="utf-8")

    result = hostile.make()

    assert result.returncode != 0
    argvs = [call["argv"] for call in hostile.calls() if call["tool"] == "docker"]
    assert any(argv[:1] == ["compose"] and "down" in argv for argv in argvs)
    assert not any(call["argv"][2:3] == ["pytest"] for call in hostile.calls())
    assert _secrets_dirs(hostile) == []


@pytest.mark.parametrize(
    ("args", "extra"),
    [
        (("LIVE_PROC_ENV=env", "LIVE_BASE_ENV=env", "LIVE_COMPOSE=docker compose"), {}),
        ((), {"MAKEFLAGS": " -- LIVE_PROC_ENV=env LIVE_BASE_ENV=env"}),
    ],
    ids=["command-line", "makeflags"],
)
def test_overriding_the_whitelist_has_no_effect(
    hostile: Hostile, args: tuple[str, ...], extra: dict[str, str]
) -> None:
    """修正 1：白名單的變數用 override，命令列與 MAKEFLAGS 都改不了。"""
    assert hostile.make(*args, **extra).returncode == 0

    for call in hostile.calls():
        assert hostile.leaked(json.dumps(call)) == set(), call["argv"][:3]
        assert call["env"].get("COMPOSE_DISABLE_ENV_FILE") == "1"


def test_a_secret_in_the_pytest_environment_is_refused(hostile: Hostile) -> None:
    """修正 1：LIVE_PYTEST_ENV 只接受 LIVE_PASS_ENV 的名稱（命令列覆寫成秘密的名稱時停止）。"""
    result = hostile.make(f"LIVE_PYTEST_ENV=DB_PASSWORD={hostile.canaries['DB_PASSWORD']}")

    assert result.returncode != 0
    assert hostile.calls() == []


def test_the_live_switch_is_required(hostile: Hostile) -> None:
    result = hostile.make(ENABLE_LIVE_LAB_TESTS="")

    assert result.returncode != 0
    assert hostile.calls() == []


# --- (b) 正向對照：不經包裝時，惡意的輸入確實有效 ----------------------------------------------


def _raw_compose(hostile: Hostile, *args: str, **changes: str) -> subprocess.CompletedProcess[str]:
    environment = {**hostile.environment(), **changes}
    environment["PATH"] = os.environ.get("PATH", "")
    # 固定的 docker compose，在暫存的 project directory 只做用戶端的解析。
    return subprocess.run(  # noqa: S603
        [
            _real_docker(),
            "compose",
            "-p",
            "secscan-live",
            "-f",
            "compose.yaml",
            "--profile",
            "app",
            "config",
            *args,
        ],
        cwd=hostile.project,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
        env=environment,
    )


def test_without_the_wrapper_the_hostile_environment_reaches_compose(hostile: Hostile) -> None:
    listing = _raw_compose(hostile, "--environment")
    resolved = _raw_compose(hostile, "--format", "json")

    assert listing.returncode == 0
    leaked_listing = bool(hostile.leaked(listing.stdout))
    assert leaked_listing
    files = {entry["file"] for entry in json.loads(resolved.stdout)["secrets"].values()}
    resolves_to_the_canary_directory = {os.path.dirname(path) for path in files} == {
        str(hostile.canary_dir)
    }
    assert resolves_to_the_canary_directory


def test_disabling_the_env_file_alone_does_not_stop_compose_env_files(hostile: Hostile) -> None:
    """G0 的調整 2：COMPOSE_DISABLE_ENV_FILE=1 擋不到 COMPOSE_ENV_FILES，白名單是必要的控制。"""
    environment = {k: v for k, v in hostile.environment().items() if k not in SECRET_NAMES}
    del environment["SECSCAN_SECRETS_DIR"]
    environment["PATH"] = os.environ.get("PATH", "")
    environment["COMPOSE_DISABLE_ENV_FILE"] = "1"
    # 固定的 docker compose，在暫存的 project directory 只做用戶端的解析。
    listing = subprocess.run(  # noqa: S603
        [
            _real_docker(),
            "compose",
            "-p",
            "secscan-live",
            "-f",
            "compose.yaml",
            "--profile",
            "app",
            "config",
            "--environment",
        ],
        cwd=hostile.project,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
        env=environment,
    )

    still_leaks = bool(hostile.leaked(listing.stdout))
    assert still_leaks


# --- (d) 靜態 -----------------------------------------------------------------------------------


def _recipe(target: str) -> str:
    match = re.search(
        rf"^{re.escape(target)}:(?!=)(.*)\n((?:\t.*\n)+)", MAKEFILE, flags=re.MULTILINE
    )
    assert match is not None, target
    return match.group(2)


def _definition(name: str) -> str:
    match = re.search(rf"^(?:override )?{name} :?= ((?:.*\\\n)*.*)$", MAKEFILE, flags=re.MULTILINE)
    assert match is not None, name
    return match.group(1)


def test_the_live_target_has_no_prerequisites() -> None:
    """D17、CSEC-12：不依賴 env、secrets、docker-check、images、build。"""
    line = re.search(r"^test-live-runner:(.*)$", MAKEFILE, flags=re.MULTILINE)
    assert line is not None

    assert line.group(1).strip() == ""


def test_the_whitelist_variables_cannot_be_overridden() -> None:
    for name in (
        "LIVE_PASS_ENV",
        "LIVE_BASE_ENV",
        "LIVE_FIXED_ENV",
        "LIVE_PROC_ENV",
        "LIVE_COMPOSE",
        "LIVE_GUARD",
    ):
        assert re.search(rf"^override {name} :?= ", MAKEFILE, flags=re.MULTILINE), name
    assert "\nLIVE_PYTEST_ENV :=\n" in MAKEFILE
    assert "\nLIVE_PYTEST_ARGS :=\n" in MAKEFILE
    assert _definition("LIVE_BASE_ENV").startswith("env -i ")


def test_the_pass_list_has_no_secret_names() -> None:
    names = set(_definition("LIVE_PASS_ENV").replace("\\\n", " ").split())

    assert names == PASS_NAMES
    assert not names & SECRET_NAMES
    assert "SECSCAN_LIVE_PROJECT" not in names
    assert "ENABLE_LIVE_LAB_TESTS" not in names


def test_every_live_call_goes_through_the_whitelist() -> None:
    recipe = _recipe("test-live-runner")
    flattened = recipe.replace("\\\n", " ")

    assert "--env-file" not in flattened
    wrappers = ("$(LIVE_PROC_ENV)", "$(LIVE_FIXED_ENV)", "$(LIVE_SECRET_FILES)")
    for match in re.finditer(r"(\S+) (?:docker|\$\(UV_RUN\)|\$\(MAKE\)) ", flattened):
        # 包含 $(...) 中的呼叫（例如 ids=$$($(LIVE_PROC_ENV) docker ps …）。
        assert match.group(1).endswith(wrappers), match.group(0)
    assert "$(COMPOSE)" not in flattened
    assert "$(LIVE_COMPOSE) up -d --wait db" in flattened
    # up 之前驗證設定。
    assert flattened.index("check-config") < flattened.index("$(LIVE_COMPOSE) up")
    assert "alembic -x dotenv=off upgrade head" in flattened
    assert "trap 'live_cleanup $$?' EXIT" in flattened
    assert "trap 'live_cleanup 130' INT TERM HUP" in flattened
    assert '"$$base"/$(LIVE_SECRETS_PREFIX)??????) rm -rf -- "$$secrets_dir"' in flattened


# --- 白名單涵蓋 Live 讀的環境變數（修正 2：以 AST 盤點）---------------------------------------

LIVE_SOURCES = [
    *sorted((ROOT / "tests" / "live").glob("*.py")),
    ROOT / "tests" / "isolation.py",
    *sorted((ROOT / "benchmarks").rglob("*.py")),
]
# 以參數間接讀取的函式：第一個參數是變數名稱。
INDIRECT_READERS = {"_required"}


def _constants(tree: ast.Module) -> dict[str, str]:
    constants = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant):
            for target in node.targets:
                if isinstance(target, ast.Name) and isinstance(node.value.value, str):
                    constants[target.id] = node.value.value
    return constants


def _name(node: ast.expr, constants: dict[str, str]) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        return constants.get(node.id)
    return None


def _environment_reads(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    constants = _constants(tree)
    # 間接讀取的函式本身以參數讀取：名稱由呼叫端的第一個參數判定。
    skipped = {
        id(inner)
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name in INDIRECT_READERS
        for inner in ast.walk(node)
    }
    names = set()
    for node in ast.walk(tree):
        if id(node) in skipped:
            continue
        if isinstance(node, ast.Call) and node.args:
            func = node.func
            reads = isinstance(func, ast.Attribute) and (
                (func.attr == "get" and "environ" in ast.unparse(func.value))
                or func.attr == "getenv"
            )
            if reads or (isinstance(func, ast.Name) and func.id in INDIRECT_READERS):
                name = _name(node.args[0], constants)
                assert name is not None, f"{path.name}: 無法判定的環境變數讀取 {ast.unparse(node)}"
                names.add(name)
        if isinstance(node, ast.Subscript) and "environ" in ast.unparse(node.value):
            name = _name(node.slice, constants)
            assert name is not None, f"{path.name}: 無法判定的環境變數讀取 {ast.unparse(node)}"
            names.add(name)
    return names


def test_the_whitelist_covers_every_variable_live_reads() -> None:
    read = set().union(*(_environment_reads(path) for path in LIVE_SOURCES))

    assert read >= {"SECSCAN_RECORD_DIR", "SECSCAN_LIVE_PROJECT", "BENCH_KEY_FILE", "BENCH_SPEC"}
    assert read <= ALLOWED, sorted(read - ALLOWED)
