"""tests/live/env_guard.py 的 unit 測試（計畫 §3.1.1；§12.8 修正 3、4、15、16、17）。

每個檢查都有會被拒絕的正向對照。docker 以記錄參數、依情境回應的替身取代（不連 daemon）。

PYTEST_DONT_REWRITE：這個模組處理秘密、canary、環境變數或設定錯誤；不改寫 assert，失敗時只顯示
原始碼與（只有名稱的）訊息，不顯示運算元的值（G1 審查）。
"""

import io
import json
import os
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

from secscan.cli.secret_files import SECRET_FILES
from tests.live import env_guard
from tests.live.env_guard import (
    GuardError,
    NetworkSpec,
    check_config,
    check_environment,
    check_images,
    check_unresolved,
    claim_networks,
    compare,
    engine,
    preflight,
    run_id,
    snapshot,
    write_diagnostic,
)

ROOT = Path(__file__).resolve().parents[2]
FILE_NAMES = sorted(item.file_name for item in SECRET_FILES)


class FakeDocker:
    def __init__(self, replies: dict[tuple[str, ...], str] | None = None) -> None:
        self.replies = replies or {}
        self.calls: list[list[str]] = []

    def __call__(self, arguments: Sequence[str]) -> str:
        self.calls.append(list(arguments))
        for prefix, reply in self.replies.items():
            if tuple(arguments[: len(prefix)]) == prefix:
                if reply == "<fail>":
                    raise GuardError("docker 失敗")
                return reply
        return ""


def _engine_docker(**overrides: str) -> FakeDocker:
    replies = {
        ("context", "show"): "orbstack\n",
        ("compose", "version"): "5.1.2\n",
        ("info",): "engine-1\n",
    }
    replies.update({tuple(key.split()): value for key, value in overrides.items()})
    return FakeDocker(replies)


# --------------------------------------------------------------------------- engine


def test_engine_reports_the_engine_id() -> None:
    assert engine({}, _engine_docker(), None) == "engine-1"
    assert engine({"DOCKER_HOST": "unix:///x.sock"}, _engine_docker(), "engine-1") == "engine-1"


@pytest.mark.parametrize(
    ("environ", "overrides", "expect", "message"),
    [
        ({"DOCKER_HOST": "tcp://10.0.0.1:2375"}, {}, None, "unix socket"),
        ({}, {"context show": "default\n"}, None, "context"),
        ({}, {"compose version": "2.29.0\n"}, None, "主版本"),
        ({}, {"info": "\n"}, None, "Engine ID"),
        ({}, {}, "engine-2", "Engine ID"),
    ],
    ids=["tcp-host", "other-context", "old-compose", "no-id", "changed-engine"],
)
def test_engine_refuses_anything_unexpected(
    environ: dict[str, str], overrides: dict[str, str], expect: str | None, message: str
) -> None:
    with pytest.raises(GuardError, match=message):
        engine(environ, _engine_docker(**overrides), expect)


# --------------------------------------------------------------------------- preflight


def test_preflight_passes_on_a_clean_machine(tmp_path: Path) -> None:
    docker = FakeDocker({("network", "ls"): "bridge\nsecscan_scan_net\n"})

    preflight(tmp_path, docker)

    assert [
        "ps",
        "-aq",
        "--no-trunc",
        "--filter",
        "label=com.docker.compose.project=secscan-live",
    ] in docker.calls


def test_preflight_refuses_a_leftover_secrets_directory(tmp_path: Path) -> None:
    (tmp_path / "secscan-live-secrets.abc123").mkdir()

    with pytest.raises(GuardError, match="拋棄式目錄"):
        preflight(tmp_path, FakeDocker())


def test_preflight_refuses_until_a_failed_cleanup_is_reviewed(tmp_path: Path) -> None:
    """上一次的清理失敗：人工確認、刪除診斷檔之前不再執行（不在不明的狀態下再建立資源）。"""
    write_diagnostic(tmp_path, str(tmp_path / "secscan-live-secrets.abc123"), ["compose down -v"])

    with pytest.raises(GuardError, match="診斷檔"):
        preflight(tmp_path, FakeDocker())


@pytest.mark.parametrize(
    "replies",
    [
        {("ps",): "c1\n"},
        {("volume", "ls"): "secscan_live_runs\n"},
        {("network", "ls"): "secscan_live_scan_net\n"},
    ],
    ids=["container", "volume", "network"],
)
def test_preflight_refuses_leftover_live_resources(
    tmp_path: Path, replies: dict[tuple[str, ...], str]
) -> None:
    with pytest.raises(GuardError, match="secscan-live 的資源"):
        preflight(tmp_path, FakeDocker(replies))


def _unlabelled_volumes(names: str) -> env_guard.Runner:
    """只有不帶 filter 的 volume ls 回傳這些名稱（沒有 compose 的專案標記）。"""

    def run(arguments: Sequence[str]) -> str:
        return names if list(arguments) == ["volume", "ls", "-q"] else ""

    return run


def test_preflight_refuses_a_live_volume_without_the_compose_label(tmp_path: Path) -> None:
    """第二輪 HIGH 條件 6：不只看專案標記，Live 名稱的 volume 也算（和清理之後的殘留檢查相同）。"""
    with pytest.raises(GuardError, match="secscan-live 的資源"):
        preflight(tmp_path, _unlabelled_volumes("secscan_db_data\nsecscan_live_runs\n"))


def test_preflight_ignores_development_volumes_positive_control(tmp_path: Path) -> None:
    preflight(tmp_path, _unlabelled_volumes("secscan_db_data\nsecscan_runs\n"))


# --------------------------------------------------------------------------- snapshot


def _dev_docker() -> FakeDocker:
    return FakeDocker(
        {
            ("ps",): "c1\n",
            ("inspect",): "/secscan-db-1 c1 2026-11-07T00:00:00Z\n",
            ("volume", "ls"): "secscan_db_data\nsecscan_live_runs\nother\n",
            ("volume", "inspect"): "secscan_db_data 2026-11-01\n",
            ("network", "ls"): (
                "secscan_scan_net n1\nbridge n0\nsecscan_default n2\nsecscan_live_scan_net n3\n"
                "secscan-live_default n4\n"
            ),
        }
    )


def test_snapshot_records_development_resources_and_file_facts(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text("DB_PASSWORD=never-printed\n", encoding="utf-8")
    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir()
    (secrets_dir / "db_password").write_text("never-printed", encoding="ascii")

    taken = snapshot(tmp_path, _dev_docker())

    assert taken["containers"] == ["/secscan-db-1 c1 2026-11-07T00:00:00Z"]
    assert taken["volumes"] == ["secscan_db_data 2026-11-01"]
    # Live 的網路不算開發環境（MEDIUM-2：否則殘留的 Live 網路會被誤報成開發環境的變化）。
    assert taken["networks"] == ["secscan_default n2", "secscan_scan_net n1"]
    assert set(taken["files"]) == {".env", "secrets/db_password"}
    leaked = "never-printed" in json.dumps(taken)
    assert not leaked


def test_snapshot_marks_missing_files(tmp_path: Path) -> None:
    assert snapshot(tmp_path, FakeDocker())["files"] == {".env": "absent"}


def test_compare_lists_only_categories_and_names(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text("A=1\n", encoding="utf-8")
    before = snapshot(tmp_path, _dev_docker())
    (tmp_path / ".env").write_text("A=2\n", encoding="utf-8")
    after = snapshot(tmp_path, FakeDocker())

    assert compare(before, before) == []
    assert compare(before, after) == ["containers", "volumes", "networks", "files:.env"]


# --------------------------------------------------------------------------- check-config


def _secrets_dir(tmp_path: Path) -> Path:
    directory = tmp_path / "secscan-live-secrets.abc123"
    directory.mkdir(mode=0o700)
    for name in FILE_NAMES:
        path = directory / name
        path.write_text("x", encoding="ascii")
        path.chmod(0o600)
    return directory


def _config(secrets_dir: Path, **changes: Any) -> dict[str, Any]:
    config: dict[str, Any] = {
        "name": "secscan-live",
        "secrets": {
            name: {"name": f"secscan-live_{name}", "file": str(secrets_dir / name)}
            for name in FILE_NAMES
        },
        "services": {
            "api": {
                "environment": {"DB_HOST": "db", "DB_PASSWORD_FILE": "/run/secrets/db_password"},
                "secrets": [
                    {"source": "db_password"},
                    "secret_encryption_keys",
                    "content_encryption_keys",
                ],
            },
            "db": {
                "environment": {"POSTGRES_PASSWORD_FILE": "/run/secrets/db_admin_password"},
                "secrets": ["db_admin_password", "db_owner_password", "db_password"],
                "volumes": [
                    {"type": "volume", "source": "db_data", "target": "/var/lib/postgresql"},
                    {
                        "type": "bind",
                        "source": str(ROOT / "deploy/postgres/initdb"),
                        "target": "/docker-entrypoint-initdb.d",
                        "read_only": True,
                    },
                ],
            },
        },
    }
    config.update(changes)
    return config


def test_a_matching_config_passes(tmp_path: Path) -> None:
    secrets_dir = _secrets_dir(tmp_path)

    check_config(_config(secrets_dir), secrets_dir, ROOT)
    # mktemp 在 TMPDIR 以 / 結尾時產生 //：兩邊都先 normpath（G0 的調整 1）。
    check_config(_config(secrets_dir), Path(f"{secrets_dir.parent}//{secrets_dir.name}"), ROOT)


def _mutated(secrets_dir: Path, case: str) -> dict[str, Any]:
    config = _config(secrets_dir)
    api = config["services"]["api"]
    db = config["services"]["db"]
    if case == "project":
        config["name"] = "secscan"
    elif case == "configs":
        config["configs"] = {}
    elif case == "missing-secret":
        del config["secrets"]["db_password"]
    elif case == "secret-elsewhere":
        # 拋棄式目錄之外、真實存在而且權限正確的檔案（例如開發的 secrets/）：只有目錄的檢查擋得下。
        elsewhere = secrets_dir.parent / "secrets"
        elsewhere.mkdir(mode=0o700, exist_ok=True)
        outside = elsewhere / "db_password"
        outside.write_text("x", encoding="ascii")
        outside.chmod(0o600)
        config["secrets"]["db_password"]["file"] = str(outside)
    elif case == "secret-environment":
        config["secrets"]["db_password"] = {"environment": "DB_PASSWORD"}
    elif case == "unknown-service":
        config["services"]["extra"] = {}
    elif case == "env-file":
        api["env_file"] = [".env"]
    elif case == "extra-environment":
        api["environment"]["DB_PASSWORD"] = "x"
    elif case == "extra-secret":
        api["secrets"].append("evidence_encryption_keys")
    elif case == "bind-elsewhere":
        db["volumes"][1]["source"] = "/Users/someone"
    elif case == "bind-writable":
        db["volumes"][1]["read_only"] = False
    elif case == "bind-on-api":
        api["volumes"] = [{"type": "bind", "source": "/", "target": "/host"}]
    return config


@pytest.mark.parametrize(
    "case",
    [
        "project",
        "configs",
        "missing-secret",
        "secret-elsewhere",
        "secret-environment",
        "unknown-service",
        "env-file",
        "extra-environment",
        "extra-secret",
        "bind-elsewhere",
        "bind-writable",
        "bind-on-api",
    ],
)
def test_config_outside_the_allowlist_is_refused(tmp_path: Path, case: str) -> None:
    secrets_dir = _secrets_dir(tmp_path)

    with pytest.raises(GuardError):
        check_config(_mutated(secrets_dir, case), secrets_dir, ROOT)


@pytest.mark.parametrize("problem", ["symlink", "mode", "links", "missing", "directory"])
def test_secret_files_must_be_private_regular_files(tmp_path: Path, problem: str) -> None:
    secrets_dir = _secrets_dir(tmp_path)
    path = secrets_dir / "db_password"
    if problem == "symlink":
        path.unlink()
        path.symlink_to(secrets_dir / "db_owner_password")
    elif problem == "mode":
        path.chmod(0o644)
    elif problem == "links":
        os.link(path, tmp_path / "second-link")
    elif problem == "missing":
        path.unlink()
    else:
        path.unlink()
        path.mkdir()

    with pytest.raises(GuardError, match="db_password"):
        check_config(_config(secrets_dir), secrets_dir, ROOT)


def test_unresolved_config_without_env_file_passes_and_with_it_is_refused() -> None:
    check_unresolved({"services": {"api": {"environment": {}}}})

    with pytest.raises(GuardError, match="env_file"):
        check_unresolved({"services": {"api": {"env_file": [".env"]}}})
    with pytest.raises(GuardError, match="include"):
        check_unresolved({"include": ["x.yaml"], "services": {}})


# --------------------------------------------------------------------------- check-environment

ALLOWED = ["PATH", "HOME", "SECSCAN_SECRETS_DIR"]


def test_environment_with_only_allowed_names_passes() -> None:
    check_environment("PATH=/bin\nHOME=/h\nCOMPOSE_PROJECT_NAME=secscan-live\nPWD=/x\n", ALLOWED)


@pytest.mark.parametrize(
    "line",
    [
        "DB_PASSWORD=x",
        "COMPOSE_ENV_FILES=/x/.env",
        "PGPASSWORD=x",
        "UNEXPECTED=1",
        "COMPOSE_FILE=x",
    ],
)
def test_environment_outside_the_allowlist_is_refused(line: str) -> None:
    with pytest.raises(GuardError):
        check_environment(f"PATH=/bin\n{line}\n", ALLOWED)


def test_environment_errors_show_names_but_never_values() -> None:
    with pytest.raises(GuardError) as caught:
        check_environment("DB_PASSWORD=secret-value-0001\n", ALLOWED)

    assert "DB_PASSWORD" in str(caught.value)
    assert "secret-value-0001" not in str(caught.value)


# --------------------------------------------------------------------------- check-images


def _images_docker(images: dict[str, str]) -> FakeDocker:
    docker = FakeDocker({("ps",): "\n".join(images) + "\n"})
    for service, image in images.items():
        docker.replies[("inspect", "--format", env_guard.IMAGE_FORMAT, service)] = (
            f"{service} {image}\n"
        )
    return docker


def test_images_match_the_built_images() -> None:
    images = {"api": "app", "runner": "app", "worker": "app", "guard": "guard", "db": "pg"}

    check_images(_images_docker(images), "app", "guard")


@pytest.mark.parametrize(
    "images",
    [
        {"api": "other", "runner": "app", "worker": "app", "guard": "guard"},
        {"api": "app", "runner": "app", "worker": "app", "guard": "other"},
        {"api": "app", "runner": "app", "guard": "guard"},
    ],
    ids=["app-image", "guard-image", "missing-worker"],
)
def test_images_that_differ_are_refused(images: dict[str, str]) -> None:
    with pytest.raises(GuardError):
        check_images(_images_docker(images), "app", "guard")


# --------------------------------------------------------------------------- networks（所有權）

OWNER = "secscan-live-secrets.Abc123"
LIVE_SPECS = [
    NetworkSpec("secscan_live_scan_net", "10.89.9.0/24", "10.89.9.0/25"),
    NetworkSpec("secscan_live_lab_net", "10.89.10.0/24", "10.89.10.0/25"),
]
# network create 回傳的完整 Network ID（G1c：所有權以它為準）。
NETWORK_IDS = {spec.name: f"{index + 1:x}" * 64 for index, spec in enumerate(LIVE_SPECS)}


def _run_directory(tmp_path: Path, owner: str = OWNER) -> Path:
    directory = tmp_path / owner
    directory.mkdir(mode=0o700)
    return directory


def _network_facts(spec: NetworkSpec, owner: str = OWNER, **changes: str) -> str:
    fields = {
        "id": NETWORK_IDS[spec.name],
        "name": spec.name,
        "internal": "true",
        "gateway": "isolated",
        "ranges": f"{spec.subnet} {spec.ip_range}",
        "labels": json.dumps({env_guard.RUN_LABEL: owner}),
    } | changes
    return "|".join(fields.values()) + "\n"


def _network_docker(owner: str = OWNER, **facts: str) -> FakeDocker:
    """兩個網路各自的 network create（以網段區分）回傳 ID；以 ID inspect 回傳 facts。"""
    docker = _engine_docker()
    for spec in LIVE_SPECS:
        label = f"{env_guard.RUN_LABEL}={owner}"
        create = ("network", "create", "--label", label, "--internal", "--opt")
        option = f"{env_guard.GATEWAY_OPTION}=isolated"
        docker.replies[(*create, option, "--subnet", spec.subnet)] = f"{NETWORK_IDS[spec.name]}\n"
        inspect = ("network", "inspect", "--format", env_guard.NETWORK_FORMAT)
        reply = facts.get(spec.name, _network_facts(spec, owner))
        docker.replies[(*inspect, NETWORK_IDS[spec.name])] = reply
    return docker


def test_the_networks_are_created_internal_isolated_and_labelled_with_the_run(
    tmp_path: Path,
) -> None:
    docker = _network_docker()

    claim_networks(docker, LIVE_SPECS, _run_directory(tmp_path), "engine-1")

    created = [call for call in docker.calls if call[:2] == ["network", "create"]]
    assert [call[-1] for call in created] == [spec.name for spec in LIVE_SPECS]
    for call, spec in zip(created, LIVE_SPECS, strict=True):
        assert call[2:11] == [
            "--label",
            f"{env_guard.RUN_LABEL}={OWNER}",
            "--internal",
            "--opt",
            f"{env_guard.GATEWAY_OPTION}=isolated",
            "--subnet",
            spec.subnet,
            "--ip-range",
            spec.ip_range,
        ]
    # 以 network create 回傳的 ID inspect（不是以名稱）。
    inspected = [call[-1] for call in docker.calls if call[:2] == ["network", "inspect"]]
    assert inspected == [NETWORK_IDS[spec.name] for spec in LIVE_SPECS]


def test_an_existing_network_is_never_shared(tmp_path: Path) -> None:
    """並行：network create 是原子的；已存在（另一次 Live 的）就停止，不檢查、不沿用。"""
    docker = _network_docker()
    docker.replies = {("network", "create"): "<fail>", **docker.replies}

    with pytest.raises(GuardError, match="另一次 Live"):
        claim_networks(docker, LIVE_SPECS, _run_directory(tmp_path), "engine-1")

    assert [call[:2] for call in docker.calls if call[0] == "network"] == [["network", "create"]]


@pytest.mark.parametrize(
    ("network", "changes", "message"),
    [
        ("secscan_live_lab_net", {"internal": "false"}, "internal"),
        ("secscan_live_scan_net", {"gateway": "nat"}, "isolated"),
        ("secscan_live_scan_net", {"ranges": "10.89.9.0/24 "}, "ip-range"),
        ("secscan_live_scan_net", {"labels": json.dumps({env_guard.RUN_LABEL: "x"})}, "這次執行"),
        ("secscan_live_scan_net", {"labels": "{}"}, "這次執行"),
        ("secscan_live_scan_net", {"id": "f" * 64}, "ID 或名稱"),
        ("secscan_live_lab_net", {"name": "secscan_live_scan_net"}, "ID 或名稱"),
    ],
    ids=[
        "not-internal",
        "gateway",
        "no-ip-range",
        "other-owner",
        "no-labels",
        "other-id",
        "other-name",
    ],
)
def test_networks_with_the_wrong_settings_are_refused(
    tmp_path: Path, network: str, changes: dict[str, str], message: str
) -> None:
    [spec] = [spec for spec in LIVE_SPECS if spec.name == network]
    docker = _network_docker(**{network: _network_facts(spec, **changes)})

    with pytest.raises(GuardError, match=message):
        claim_networks(docker, LIVE_SPECS, _run_directory(tmp_path), "engine-1")


def test_unparsable_network_facts_are_refused(tmp_path: Path) -> None:
    docker = _network_docker(secscan_live_lab_net="true\n")

    with pytest.raises(GuardError, match="無法確認"):
        claim_networks(docker, LIVE_SPECS, _run_directory(tmp_path), "engine-1")


@pytest.mark.parametrize(
    "names",
    [
        ("secscan_scan_net", "secscan_live_lab_net"),
        ("secscan_live_scan_net",),
        ("secscan_live_scan_net", "secscan_live_lab_net", "secscan_lab_net"),
    ],
    ids=["dev-network", "only-one", "extra"],
)
def test_only_the_two_live_networks_can_be_created(tmp_path: Path, names: tuple[str, ...]) -> None:
    docker = _network_docker()
    specs = [NetworkSpec(name, "10.0.0.0/24", "10.0.0.0/25") for name in names]

    with pytest.raises(GuardError, match="Live 的兩個網路"):
        claim_networks(docker, specs, _run_directory(tmp_path), "engine-1")

    assert docker.calls == []


@pytest.mark.parametrize(
    ("path", "base"),
    [
        ("/srv/x/secscan-live-secrets.ab", None),
        ("/srv/elsewhere/secscan-live-secrets.Abc123", "/srv/x"),
    ],
    ids=["bad-name", "outside-base"],
)
def test_the_run_id_must_be_the_disposable_directory(path: str, base: str | None) -> None:
    with pytest.raises(GuardError, match="無法確認這次執行"):
        run_id(Path(path), Path(base) if base else None)

    assert run_id(Path(f"/srv/x/{OWNER}/"), Path("/srv/x/")) == OWNER


# --------------------------------------------------------------------------- CLI


def test_the_cli_prints_names_and_returns_non_zero_on_failure(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(env_guard, "docker", FakeDocker())
    monkeypatch.setattr("sys.stdin", io.StringIO("DB_PASSWORD=secret-value-0002\n"))

    assert env_guard.main(["check-environment", "--allow", "PATH"]) == env_guard.EXIT_FAILURE

    out, err = capsys.readouterr()
    assert out == ""
    assert "DB_PASSWORD" in err
    assert "secret-value-0002" not in err


def test_the_cli_runs_each_subcommand(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    docker = _engine_docker()
    monkeypatch.setattr(env_guard, "docker", docker)
    secrets_dir = _secrets_dir(tmp_path)
    for name in ("base", "runs"):
        (tmp_path / name).mkdir()
    run_directory = _run_directory(tmp_path / "runs")
    runs = [
        (["engine"], ""),
        (["preflight", "--base", str(tmp_path / "base")], ""),
        (["snapshot", "--root", str(tmp_path)], ""),
        (
            ["check-config", "--secrets-dir", str(secrets_dir), "--root", str(ROOT)],
            json.dumps(_config(secrets_dir)),
        ),
        (["check-unresolved"], json.dumps({"services": {}})),
        (["check-environment", "--allow", "PATH"], "PATH=/bin\n"),
        (
            [
                "networks",
                *("--secrets-dir", str(run_directory), "--engine", "engine-1"),
                *("--network", "secscan_live_scan_net", "10.89.9.0/24", "10.89.9.0/25"),
                *("--network", "secscan_live_lab_net", "10.89.10.0/24", "10.89.10.0/25"),
            ],
            "",
        ),
    ]
    docker.replies.update(_network_docker().replies)
    for argv, stdin in runs:
        monkeypatch.setattr("sys.stdin", io.StringIO(stdin))
        assert env_guard.main(argv) == env_guard.EXIT_OK, argv
    snapshot_text = capsys.readouterr().out.splitlines()[2]
    monkeypatch.setattr("sys.stdin", io.StringIO(snapshot_text))
    assert env_guard.main(["compare", "--root", str(tmp_path)]) == env_guard.EXIT_OK
    (tmp_path / ".env").write_text("changed\n", encoding="utf-8")
    monkeypatch.setattr("sys.stdin", io.StringIO(snapshot_text))
    assert env_guard.main(["compare", "--root", str(tmp_path)]) == env_guard.EXIT_FAILURE


def test_the_cli_reports_file_errors_without_a_traceback(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    def refuse(_root: Path) -> dict[str, str]:
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(env_guard, "docker", lambda _arguments: "")
    monkeypatch.setattr(env_guard, "_file_facts", refuse)
    monkeypatch.setattr("sys.stdin", io.StringIO(""))

    code = env_guard.main(["snapshot", "--root", str(tmp_path)])

    assert code == env_guard.EXIT_FAILURE
    assert "無法存取檔案（PermissionError）" in capsys.readouterr().err


def test_invalid_json_input_is_refused(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    for stdin in ("", "[1]"):
        monkeypatch.setattr("sys.stdin", io.StringIO(stdin))
        assert env_guard.main(["check-unresolved"]) == env_guard.EXIT_FAILURE
    assert "JSON" in capsys.readouterr().err
