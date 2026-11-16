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

PYTEST_DONT_REWRITE：這個模組處理秘密、canary、環境變數或設定錯誤；不改寫 assert，失敗時只顯示
原始碼與（只有名稱的）訊息，不顯示運算元的值（G1 審查）。
"""

import ast
import hashlib
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
from tests import conftest as root_conftest
from tests.isolation import BLOCKED_DOCKER_HOST
from tests.live import env_guard
from tests.live_session import LIVE_PRESERVED_ENV

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
LIVE_COMPOSE_ARGUMENTS = ["compose", "-p", "secscan-live", "-f", "compose.yaml", "--profile", "app"]
# GNU make 對 -n、-q、-t 的處理（安全審查 H1）：含 $(MAKE) 的 recipe 行在這三種模式下仍會執行。
DRY_RUN_FLAGS = ("-n", "-q", "-t")
# 程序本身加上的變數（shell）：不是從 shell 帶進來的設定。Live 的 recipe 不呼叫子 make，所以呼叫的
# 環境不會有 MAKEFLAGS、MAKELEVEL（env -i 之後也沒有）。
PLUMBING = {
    "PWD",
    "OLDPWD",
    "SHLVL",
    "_",
    "__CF_USER_TEXT_ENCODING",
}


def _live_env_names() -> set[str]:
    match = re.search(r"^override LIVE_ENV := ((?:.*\\\n)*.*)$", MAKEFILE, flags=re.MULTILINE)
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

# 假的 docker：狀態（網路與所有權的標記、Live stack 的容器與 volume）存在 JSON 檔。容器有完整的
# ID 與實際接的網路：guard 同時接在兩個 Live 網路上（第二輪 HIGH）。docker rm 收到重複的 ID 時回傳
# 失敗：這是審查者依 docker CLI 與 daemon 的原始碼推論的行為（第二個刪除請求衝突），沒有以真的
# Docker 驗證；替身照最嚴格的推論失敗，去重是否有效才測得出來。網路上還有容器時 network rm 失敗。
# scenario 讓某一步失敗或預先放入資源（另一次執行的網路、其他專案的容器）。compose config 交給真的
# docker compose（只在用戶端解析）。
_FAKE_DOCKER = """#!{python}
import hashlib, json, os, subprocess, sys
args = sys.argv[1:]
with open({log!r}, "a") as log:
    log.write(json.dumps({{"tool": "docker", "argv": args, "env": dict(os.environ)}}) + "\\n")
scenario = json.loads(open({scenario!r}).read())
state = json.loads(open({state!r}).read())
state.setdefault("volumes", [])
state.setdefault("compose_networks", [])
def save():
    open({state!r}, "w").write(json.dumps(state))
def out(text="", code=0):
    sys.stdout.write(text)
    sys.exit(code)
def option(name):
    return args[args.index(name) + 1] if name in args else ""
def cid(name):
    return hashlib.sha256(name.encode()).hexdigest()
def nets(container):
    return container.get("networks") or [container["network"]]
def lines(items):
    return "".join(f"{{item}}\\n" for item in items)
ranges = {{"secscan_live_scan_net": "10.89.9.0/24 10.89.9.0/25",
          "secscan_live_lab_net": "10.89.10.0/24 10.89.10.0/25"}}
LIVE = "secscan-live"
COMPOSE_NETS = ["secscan-live_default", "secscan-live_control_net", "secscan-live_docker_net"]
def start(services):
    for service, attached in services:
        state["containers"].append(
            {{"id": cid(service), "service": service, "project": LIVE, "networks": attached}})
    state["compose_networks"] = COMPOSE_NETS
if args[:2] == ["context", "show"]:
    out("orbstack\\n")
if args[:1] in (["version"], ["pull"]):
    out()
if args[:1] == ["info"]:
    out(state.get("engine", "engine-1") + "\\n")
if args[:1] == ["rm"]:
    ids = [item for item in args[1:] if not item.startswith("-")]
    state["containers"] = [c for c in state["containers"] if c["id"] not in ids]
    save()
    if len(ids) != len(set(ids)):
        sys.stderr.write("removal of container is already in progress\\n")
        out(code=1)
    out()
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
        if "db" in args:
            start([("db", ["secscan-live_default", "secscan-live_control_net"])])
            state["volumes"].append({{"name": "secscan-live_db_data", "project": LIVE}})
        else:
            state["up"] = True
            start([("api", ["secscan-live_default", "secscan-live_control_net"]),
                   ("runner", ["secscan-live_control_net", "secscan-live_docker_net"]),
                   ("worker", ["secscan-live_control_net"]),
                   ("socket-proxy", ["secscan-live_docker_net"]),
                   ("guard", ["secscan_live_scan_net", "secscan_live_lab_net"])])
            state["volumes"].append({{"name": "secscan_live_runs", "project": LIVE}})
            state["containers"] += scenario.get("extra_containers", [])
            if scenario.get("networks_vanish"):
                state["networks"] = {{}}
            if scenario.get("engine_changes"):
                state["engine"] = "engine-2"
        save()
        out()
    if "down" in args:
        if scenario.get("down_fails"):
            out(code=1)
        state["up"] = False
        state["containers"] = [c for c in state["containers"] if c.get("project") != LIVE]
        state["volumes"] = [v for v in state["volumes"] if v["project"] != LIVE]
        state["compose_networks"] = []
        save()
        out()
    out()
if args[:1] == ["ps"]:
    target = option("--filter")
    if target == "label=com.docker.compose.project=secscan-live":
        out(lines(c["id"] for c in state["containers"] if c.get("project") == LIVE))
    if target.startswith("network="):
        out(lines(c["id"] for c in state["containers"] if target[8:] in nets(c)))
    out()
if args[:1] == ["inspect"]:
    fmt = option("--format")
    found = [c for c in state["containers"] if c["id"] == args[-1]]
    if not found:
        out(code=1)
    [container] = found
    if "NetworkSettings" in fmt:
        project = container.get("project") or "<no value>"
        out(container["id"] + "|" + project + "|" + " ".join(nets(container)) + " \\n")
    service = container.get("service", "")
    out(service + (" sha256:guard\\n" if service == "guard" else " sha256:app\\n"))
if args[:2] == ["image", "inspect"]:
    out("sha256:guard\\n" if args[-1].startswith("secscan-guard") else "sha256:app\\n")
if args[:2] == ["volume", "ls"]:
    labelled = "--filter" in args
    out(lines(v["name"] for v in state["volumes"] if not labelled or v["project"] == LIVE))
if args[:2] == ["network", "ls"]:
    out(lines([*state["networks"], *state["compose_networks"]]))
if args[:2] == ["network", "create"]:
    name = args[-1]
    if name in state["networks"] or name in scenario.get("taken", []):
        sys.stderr.write("network with name " + name + " already exists\\n")
        out(code=1)
    state["networks"][name] = option("--label").split("=", 1)[1]
    save()
    out()
if args[:2] == ["network", "rm"]:
    if scenario.get("network_rm_fails"):
        out(code=1)
    for name in args[2:]:
        if any(name in nets(c) for c in state["containers"]):
            sys.stderr.write("error while removing network: network has active endpoints\\n")
            out(code=1)
        state["networks"].pop(name, None)
    save()
    out()
if args[:2] == ["network", "inspect"]:
    name = args[-1]
    if name not in state["networks"]:
        out(code=1)
    fmt = option("--format")
    label = state["networks"][name] or "<no value>"
    if "|" in fmt:
        out("true|isolated|" + ranges[name] + "|" + label + "\\n")
    out(label + "\\n")
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

# $(MAKE) 指向這個包裝（命令列的 MAKE=）：記下每一次遞迴的呼叫，再交給真的 make。bench 的遞迴沒有
# -f（在 repo 的根目錄執行）；暫存的 project directory 沒有 Makefile，所以補上 repo 的 Makefile。
_FAKE_MAKE = """#!{python}
import json, os, sys
args = sys.argv[1:]
with open({log!r}, "a") as log:
    log.write(json.dumps({{"tool": "make", "argv": args, "env": dict(os.environ)}}) + "\\n")
if "-f" not in args:
    args = ["-f", {makefile!r}, *args]
os.execv({real_make!r}, [{real_make!r}, *args])
"""


def _real_docker() -> str:
    cli = shutil.which("docker")
    if cli is None:
        pytest.skip("沒有安裝 docker CLI")
    return cli


def _real_make() -> str:
    make = shutil.which("make")
    assert make is not None, "需要 make"
    return make


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
        self.state = root / "state.json"
        self.state.write_text(
            json.dumps({"up": False, "networks": {}, "containers": []}), encoding="utf-8"
        )
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
            "real_make": _real_make(),
            "makefile": str(MAKEFILE_PATH),
        }
        for name, template in (("docker", _FAKE_DOCKER), ("uv", _FAKE_UV), ("make", _FAKE_MAKE)):
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

    def make(
        self, *args: str, target: str = "test-live-runner", **extra_env: str
    ) -> subprocess.CompletedProcess[str]:
        # 固定的 make 與 repo 的 Makefile；docker 與 uv 是假的執行檔，$(MAKE) 是記錄呼叫的包裝。
        return subprocess.run(  # noqa: S603
            [
                _real_make(),
                "--no-print-directory",
                "-f",
                str(MAKEFILE_PATH),
                f"MAKE={self.bin / 'make'}",
                "UV_RUN=uv run --locked",
                *args,
                target,
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

    def docker_argvs(self) -> list[list[str]]:
        return [call["argv"] for call in self.calls() if call["tool"] == "docker"]

    def set_scenario(self, **scenario: object) -> None:
        self.scenario.write_text(json.dumps(scenario), encoding="utf-8")

    def docker_state(self) -> dict[str, Any]:
        loaded: dict[str, Any] = json.loads(self.state.read_text(encoding="utf-8"))
        return loaded

    def set_docker_state(self, **changes: object) -> None:
        self.state.write_text(json.dumps(self.docker_state() | changes), encoding="utf-8")

    def diagnostics(self) -> list[Path]:
        return sorted(self.tmpdir.glob("secscan-live-cleanup-failed.*"))

    def redact(self, text: str) -> str:
        """訊息中的 canary 換成名稱：assert 的訊息不輸出原始值。"""
        for name, value in self.canaries.items():
            text = text.replace(value, f"<{name}>")
        return text.replace(str(self.canary_dir), "<SECSCAN_SECRETS_DIR>")

    def label(self, call: dict[str, Any]) -> str:
        """呼叫的前三個參數（遮罩之後），作為 assert 的訊息。"""
        return self.redact(json.dumps(call["argv"][:3]))

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
        sorted(hostile.leaked(result.stdout + result.stderr))
        or hostile.redact(result.stderr)[-2000:]
    )
    calls = hostile.calls()
    assert calls
    pattern = re.compile(
        rf"{re.escape(str(hostile.tmpdir))}/secscan-live-secrets\.[A-Za-z0-9]{{6}}"
    )
    directories = set()
    # Live 的 recipe 不遞迴呼叫 make（安全審查 H1：含 $(MAKE) 的行在 -n、-q、-t 下仍會執行）。
    assert [call["tool"] for call in calls if call["tool"] == "make"] == []
    for call in calls:
        environment = call["env"]
        leaked = hostile.leaked(json.dumps(call))
        assert leaked == set(), hostile.label(call)
        unexpected = set(environment) - ALLOWED - set(ALEMBIC_FILES) - PLUMBING
        assert unexpected == set(), (hostile.label(call), sorted(unexpected))
        for key, value in FIXED.items():
            assert environment.get(key) == value, (hostile.label(call), key)
        directory = environment["SECSCAN_SECRETS_DIR"]
        # mktemp 之前（engine、preflight、snapshot）是不存在的佔位路徑（D16：一律非空）。
        assert directory == PLACEHOLDER or pattern.fullmatch(directory), hostile.label(call)
        assert environment["SECSCAN_LIVE_SECRETS_DIR"] == directory
        if directory != PLACEHOLDER:
            directories.add(directory)
        if call["argv"][:1] == ["compose"] and "version" not in call["argv"]:
            assert directory != PLACEHOLDER, hostile.label(call)
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
            assert argv[1:5] == ["-p", "secscan-live", "-f", "compose.yaml"], argv[:6]
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
    hostile.set_scenario(up_fails=True)

    result = hostile.make()

    assert result.returncode != 0
    argvs = hostile.docker_argvs()
    assert any(argv[:1] == ["compose"] and "down" in argv for argv in argvs)
    assert not any(call["argv"][2:3] == ["pytest"] for call in hostile.calls())
    assert _secrets_dirs(hostile) == []
    assert hostile.docker_state()["networks"] == {}


# --- 所有權與清理（G1 審查 M2、MEDIUM-1、2；破壞性的情境只用假的 docker）----------------------

LIVE_NETWORK_NAMES = {"secscan_live_scan_net", "secscan_live_lab_net"}


def _destructive(argvs: list[list[str]]) -> list[list[str]]:
    """會刪除或建立資源的呼叫（down、rm、network create／rm）。"""
    return [
        argv
        for argv in argvs
        if argv[:1] == ["rm"]
        or argv[:2] in (["network", "rm"], ["network", "create"])
        or (argv[:1] == ["compose"] and "down" in argv)
    ]


def test_the_networks_are_claimed_and_cleaned_up_by_this_run_only(hostile: Hostile) -> None:
    assert hostile.make().returncode == 0
    argvs = hostile.docker_argvs()
    [directory] = {
        call["env"]["SECSCAN_SECRETS_DIR"]
        for call in hostile.calls()
        if call["env"].get("SECSCAN_SECRETS_DIR", PLACEHOLDER) != PLACEHOLDER
    }
    owner = os.path.basename(directory)

    created = [argv for argv in argvs if argv[:2] == ["network", "create"]]
    assert {argv[-1] for argv in created} == LIVE_NETWORK_NAMES
    assert all(argv[2:4] == ["--label", f"secscan.live.run={owner}"] for argv in created)
    removed = [argv for argv in argvs if argv[:2] == ["network", "rm"]]
    assert {argv[2] for argv in removed} == LIVE_NETWORK_NAMES
    [down] = [argv for argv in argvs if argv[:1] == ["compose"] and "down" in argv]
    assert down == [*LIVE_COMPOSE_ARGUMENTS, "down", "-v", "--remove-orphans"]
    # 網路在任何建立 stack 的動作（build、up）之前就取得所有權。
    first_claim = argvs.index(created[0])
    assert first_claim < min(
        index for index, argv in enumerate(argvs) if argv[:1] == ["compose"] and "build" in argv
    )
    assert hostile.docker_state()["networks"] == {}
    assert hostile.diagnostics() == []


def test_a_running_live_is_left_alone(hostile: Hostile) -> None:
    """並行：另一次 Live 已經建立了網路與容器，這次在 preflight 就停止，不碰它的任何資源。"""
    others = dict.fromkeys(LIVE_NETWORK_NAMES, "secscan-live-secrets.Other1")
    hostile.set_docker_state(
        networks=others,
        containers=[
            {"id": "c-other", "project": "secscan-live", "network": "secscan_live_lab_net"}
        ],
    )

    result = hostile.make()

    assert result.returncode != 0
    assert _destructive(hostile.docker_argvs()) == []
    assert hostile.docker_state()["networks"] == others
    assert _secrets_dirs(hostile) == []


def test_losing_the_race_for_a_network_removes_only_its_own_directory(hostile: Hostile) -> None:
    """preflight 之後另一次 Live 先建立了網路：這次取不到所有權，只刪自己的拋棄式目錄。"""
    hostile.set_scenario(taken=["secscan_live_scan_net"])

    result = hostile.make()

    assert result.returncode != 0
    destructive = _destructive(hostile.docker_argvs())
    assert [argv[:2] for argv in destructive] == [["network", "create"]]
    assert not any(call["argv"][2:3] == ["pytest"] for call in hostile.calls())
    assert _secrets_dirs(hostile) == []
    assert hostile.diagnostics() == []


def _cid(name: str) -> str:
    """假的 docker 的完整容器 ID（stack 的服務以服務名稱計算）。"""
    return hashlib.sha256(name.encode()).hexdigest()


def test_a_container_of_another_project_is_never_removed(hostile: Hostile) -> None:
    """Live 的網路上出現其他 compose 專案（例如開發的 secscan）的容器：不刪除，清理以失敗回報。"""
    dev, probe = _cid("c-dev"), _cid("c-probe")
    hostile.set_scenario(
        extra_containers=[
            {"id": dev, "project": "secscan", "network": "secscan_live_scan_net"},
            {"id": probe, "project": "", "network": "secscan_live_scan_net"},
        ]
    )

    result = hostile.make()

    assert result.returncode != 0
    removed = [argv for argv in hostile.docker_argvs() if argv[:1] == ["rm"]]
    assert sorted(argv[-1] for argv in removed) == sorted([_cid("guard"), probe])
    assert all(argv == ["rm", "-f", "-v", argv[-1]] for argv in removed)
    assert dev in {item["id"] for item in hostile.docker_state()["containers"]}
    [diagnostic] = hostile.diagnostics()
    assert stat.S_IMODE(diagnostic.stat().st_mode) == 0o600
    assert dev[:12] in diagnostic.read_text(encoding="utf-8")
    assert dev[:12] in result.stderr


@pytest.mark.parametrize("failure", ["down_fails", "network_rm_fails"])
def test_a_cleanup_failure_is_reported_and_blocks_the_next_run(
    hostile: Hostile, failure: str
) -> None:
    hostile.set_scenario(**{failure: True})

    result = hostile.make()

    assert result.returncode != 0
    [diagnostic] = hostile.diagnostics()
    text = diagnostic.read_text(encoding="utf-8")
    leaked = hostile.leaked(text + result.stderr)
    assert leaked == set()
    assert "清理沒有完成" in result.stderr
    # 下一次在 preflight 就停止：人工確認、刪除診斷檔之前不再執行。
    hostile.set_scenario()
    hostile.log.write_text("", encoding="utf-8")
    again = hostile.make()
    assert again.returncode != 0
    assert "診斷檔" in again.stderr
    assert _destructive(hostile.docker_argvs()) == []


@pytest.mark.parametrize(
    ("args", "extra"),
    [
        (
            (
                "LIVE_PROJECT=secscan",
                "LIVE_SCAN_NET=secscan_scan_net",
                "LIVE_LAB_NET=secscan_lab_net",
                "LIVE_COMPOSE_FILE=other.yaml",
                "DB_FILE=other.yaml",
                "LIVE_SECRETS_PREFIX=secscan-",
                "LIVE_ENV=SECSCAN_RUNS_VOLUME=secscan_runs",
            ),
            {},
        ),
        (
            (),
            {
                "MAKEFLAGS": " -- LIVE_PROJECT=secscan LIVE_SCAN_NET=secscan_scan_net "
                "LIVE_LAB_NET=secscan_lab_net LIVE_COMPOSE_FILE=other.yaml"
            },
        ),
        (("-e",), {"LIVE_PROJECT": "secscan", "LIVE_SCAN_NET": "secscan_scan_net"}),
    ],
    ids=["command-line", "makeflags", "environment-override"],
)
def test_the_live_identity_cannot_be_overridden(
    hostile: Hostile, args: tuple[str, ...], extra: dict[str, str]
) -> None:
    """M2（HIGH）：LIVE_PROJECT=secscan 曾讓清理段以 -p secscan 執行 down -v（會刪掉開發的
    db_data）。"""
    hostile.set_scenario(up_fails=True)

    hostile.make(*args, **extra)

    argvs = hostile.docker_argvs()
    assert any(argv[:1] == ["compose"] and "down" in argv for argv in argvs)
    for argv in argvs:
        if argv[:1] == ["compose"] and argv[1:2] != ["version"]:
            assert argv[1:5] == ["-p", "secscan-live", "-f", "compose.yaml"], argv[:6]
        assert not {"secscan_scan_net", "secscan_lab_net", "other.yaml"} & set(argv), argv[:3]
    for call in hostile.calls():
        assert call["env"].get("SECSCAN_RUNS_VOLUME") in (None, "secscan_live_runs")
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
        leaked = hostile.leaked(json.dumps(call))
        assert leaked == set(), hostile.label(call)
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


def _files(root: Path) -> set[str]:
    """root 之下所有的路徑（不含假執行檔的呼叫紀錄）：-t 會 touch 出新檔，Live 會建立拋棄式目錄。"""
    return {str(path.relative_to(root)) for path in root.rglob("*") if path.name != "calls.log"}


@pytest.mark.parametrize("flag", DRY_RUN_FLAGS)
@pytest.mark.parametrize(
    "target", ["test-live-runner", "test-live-secrets", "bench", "test-live-lab"]
)
def test_dry_run_flags_execute_nothing(hostile: Hostile, flag: str, target: str) -> None:
    """安全審查 H1（HIGH-A）：make -n／-q／-t 不得執行 Live 的任何一步（以為是預覽，實際卻跑了
    Live）。

    惡意的環境照樣打開 ENABLE_LIVE_LAB_TESTS：判斷不能依賴開關或旗標，Live 的 recipe 本身不得含
    $(MAKE)（GNU make 對含 $(MAKE) 的行在這三種模式下仍會執行）。bench 以 $(MAKE) 遞迴呼叫
    test-live-runner：子 make 繼承 -n、-q、-t，所以同樣什麼都不執行。
    """
    before = _files(hostile.root)

    result = hostile.make(flag, target=target)

    # -q 對 phony 的目標回報「不是最新的」（1）；-n、-t 是 0。
    assert result.returncode in (0, 1)
    side_effects = [call["tool"] for call in hostile.calls() if call["tool"] != "make"]
    assert side_effects == []
    recursions = [call for call in hostile.calls() if call["tool"] == "make"]
    # Live 的 recipe 本身不遞迴；只有 bench 遞迴呼叫 test-live-runner（-q 在前置的 phony 目標就
    # 停止，不一定走到遞迴），而且子 make 繼承了預覽的旗標。
    if target != "bench":
        assert recursions == []
    elif flag != "-q":
        assert len(recursions) == 1
    for call in recursions:
        assert "test-live-runner" in call["argv"]
        assert flag[1] in _short_flags(call["env"].get("MAKEFLAGS", ""))
    assert _files(hostile.root) == before


def _short_flags(makeflags: str) -> str:
    """MAKEFLAGS 中的單字母旗標（GNU make 3.81 的子 make：` --no-print-directory -n -- 變數`）。"""
    words = makeflags.split(" -- ", 1)[0].split()
    return "".join(word.lstrip("-") for word in words if not word.startswith("--"))


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


def _expanded(text: str, depth: int = 0) -> str:
    """text 引用的 Makefile 變數，依定義逐層展開成文字（只看 Makefile 中定義的變數）。"""
    assert depth < 10, "變數的引用太深"
    expanded = [text]
    for name in set(re.findall(r"\$\((\w+)\)", text)):
        match = re.search(rf"^(?:override )?{name} :?= ((?:.*\\\n)*.*)$", MAKEFILE, re.MULTILINE)
        if match is not None:
            expanded.append(_expanded(match.group(1), depth + 1))
    return "\n".join(expanded)


def test_the_live_recipe_never_recurses_into_make() -> None:
    """安全審查 H1：GNU make 對含 $(MAKE)（或 ${MAKE}、行首的 +）的行，在 -n、-q、-t 下仍會執行。

    Live 的 recipe 不得直接或經由變數引用 MAKE；網路改由 env_guard 建立（不再呼叫子 make 的
    ensure-net）。
    """
    recipe = _recipe("test-live-runner")

    assert re.findall(r"\$[({]MAKE[)}]", _expanded(recipe)) == []
    assert "${" not in recipe.replace("$${", "")
    assert not [line for line in recipe.splitlines() if line.lstrip("\t@-").startswith("+")]


def test_the_checks_come_before_any_side_effect() -> None:
    """HIGH-A：開關與 LIVE_PYTEST_ENV 的檢查和整個流程在同一個邏輯行、而且在最前面：即使這一行在
    預覽模式下被執行，也一定先經過檢查。"""
    recipe = _recipe("test-live-runner").rstrip("\n").split("\n")
    flattened = " ".join(line.removesuffix("\\") for line in recipe)

    assert all(line.endswith("\\") for line in recipe[:-1])
    assert flattened.startswith('\t@[ "$$ENABLE_LIVE_LAB_TESTS" = 1 ] || {')
    first_effect = min(flattened.index(word) for word in ("$(LIVE_GUARD)", "mktemp", " docker "))
    assert flattened.index("LIVE_PYTEST_ENV 只接受") < first_effect


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


def test_the_trap_is_installed_only_after_the_preflight_and_before_the_claim() -> None:
    """MEDIUM-1：preflight 拒絕（例如另一次 Live 正在執行）時沒有 trap，不會拆掉別人的 stack；
    拋棄式目錄建立之後才安裝，立刻接著取得網路的所有權。清理只由 env_guard 執行（不直接 rm）。"""
    flattened = _recipe("test-live-runner").replace("\\\n", " ")
    trap = flattened.index("trap 'live_cleanup $$?' EXIT")

    assert "trap 'live_cleanup 130' INT TERM HUP" in flattened
    for earlier in ("$(LIVE_GUARD) engine)", "$(LIVE_GUARD) preflight", "snapshot=", "mktemp -d"):
        assert flattened.index(earlier) < trap, earlier
    claim = flattened.index('$(LIVE_GUARD) networks --secrets-dir "$$secrets_dir"')
    assert trap < claim
    assert claim < min(flattened.index(word) for word in ("generate-secret-files", "docker pull"))
    start = flattened.index("live_cleanup() {")
    cleanup = flattened[start : flattened.index("}; ", start)]
    assert '$(LIVE_GUARD) cleanup --base "$$base" --secrets-dir "$$secrets_dir"' in cleanup
    assert not re.search(r"\brm\b|\bdown\b|network rm", cleanup)
    assert not re.search(r"\brm -rf\b", flattened)


def test_the_live_identity_is_fixed_and_matches_the_guard() -> None:
    """M2（HIGH）：專案、網路、volume、compose 檔與拋棄式目錄的前綴都用 override，而且和 env_guard
    清理時使用的常數一致（清理不依賴 make 的變數）。"""
    for name in (
        "LIVE_PROJECT",
        "LIVE_COMPOSE_FILE",
        "LIVE_SCAN_NET",
        "LIVE_SCAN_SUBNET",
        "LIVE_SCAN_IP_RANGE",
        "LIVE_LAB_NET",
        "LIVE_LAB_SUBNET",
        "LIVE_LAB_IP_RANGE",
        "LIVE_ENV",
        "LIVE_SECRETS_PREFIX",
        "LIVE_ALLOWED_NAMES",
        "LIVE_SECRET_FILES",
    ):
        assert re.search(rf"^override {name} :?= ", MAKEFILE, flags=re.MULTILINE), name
    assert _definition("LIVE_PROJECT") == env_guard.LIVE_PROJECT
    assert _definition("LIVE_COMPOSE_FILE") == env_guard.COMPOSE_FILE
    assert {_definition("LIVE_SCAN_NET"), _definition("LIVE_LAB_NET")} == env_guard.LIVE_NETWORKS
    assert _definition("LIVE_SECRETS_PREFIX") == env_guard.SECRETS_PREFIX
    assert "-p $(LIVE_PROJECT) -f $(LIVE_COMPOSE_FILE) " in _definition("LIVE_COMPOSE").replace(
        "\\\n\t", ""
    )
    assert list(env_guard.LIVE_COMPOSE) == LIVE_COMPOSE_ARGUMENTS
    volumes = {
        value
        for item in _definition("LIVE_ENV").replace("\\\n", " ").split()
        for key, value in [item.split("=", 1)]
        if key.endswith("_VOLUME")
    }
    assert volumes
    assert all(volume.startswith(env_guard.LIVE_RESOURCE_PREFIXES) for volume in volumes)


# --- 白名單涵蓋 Live 讀的環境變數（修正 2：以 AST 盤點）---------------------------------------

LIVE_SOURCES = [
    *sorted((ROOT / "tests" / "live").glob("*.py")),
    ROOT / "tests" / "isolation.py",
    ROOT / "tests" / "live_session.py",
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


def test_the_variables_live_needs_survive_the_root_isolation() -> None:
    """HIGH-1：根 conftest 的 _isolate_app_settings 對每個測試刪除的變數中，Live 會讀的（AST 盤點）
    與 compose.yaml 必填的（${X:?…}），都必須在授權的 live 測試保留；保留清單也不能有用不到的
    名稱。"""
    deleted = {
        *root_conftest.DB_ENV_KEYS,
        *root_conftest.SECRET_ENV_KEYS,
        *root_conftest.RETENTION_ENV_KEYS,
        *root_conftest.RUNNER_ENV_KEYS,
    }
    required = set(re.findall(r"\$\{(\w+):\?", (ROOT / "compose.yaml").read_text(encoding="utf-8")))
    needed = set().union(*(_environment_reads(path) for path in LIVE_SOURCES)) | required

    assert required == {"SECSCAN_SECRETS_DIR"}
    assert (needed & deleted) - LIVE_PRESERVED_ENV == set()
    assert needed & deleted >= LIVE_PRESERVED_ENV
    # 秘密的名稱不得保留（授權的 live 測試也一樣不帶秘密）。
    assert not LIVE_PRESERVED_ENV & SECRET_NAMES


# --- test-live-lab 的靶機映像（G1 審查：lab-images 由 Live 路徑呼叫，必須經過白名單）-------------


def test_the_lab_images_are_pulled_through_the_whitelist(hostile: Hostile) -> None:
    """test-live-lab 不依賴 lab-images（以 make 的完整環境、讀專案目錄 .env 的 compose 執行）；
    靶機映像在 Live 的 recipe 內、經過白名單 pull。"""
    assert hostile.make(target="test-live-lab").returncode == 0

    pulls = [
        call
        for call in hostile.calls()
        if call["tool"] == "docker"
        and "compose.lab.yaml" in call["argv"]
        and "pull" in call["argv"]
    ]
    [pull] = pulls
    environment = pull["env"]
    unexpected = set(environment) - ALLOWED - PLUMBING
    leaked = hostile.leaked(json.dumps(pull))
    assert pull["argv"][:5] == ["compose", "-p", "secscan-live", "-f", "compose.lab.yaml"]
    assert environment.get("COMPOSE_DISABLE_ENV_FILE") == "1"
    assert unexpected == set(), sorted(unexpected)
    assert leaked == set(), sorted(leaked)


def test_other_live_targets_do_not_pull_the_lab_images(hostile: Hostile) -> None:
    assert hostile.make().returncode == 0

    assert not [argv for argv in hostile.docker_argvs() if "compose.lab.yaml" in argv]


def test_the_lab_target_has_no_unwrapped_prerequisite() -> None:
    line = re.search(r"^test-live-lab: (?!LIVE_)(.*)$", MAKEFILE, flags=re.MULTILINE)
    assert line is not None

    assert line.group(1).split() == ["test-live-runner"]
    assert _definition("LIVE_LAB_PULL").startswith(
        "$(LIVE_PROC_ENV) docker compose -p $(LIVE_PROJECT)"
    )
    assert re.search(r"^override LIVE_LAB_PULL = ", MAKEFILE, flags=re.MULTILINE)
    assert re.search(r"^override LIVE_LAB_FILE := compose.lab.yaml$", MAKEFILE, flags=re.MULTILINE)
