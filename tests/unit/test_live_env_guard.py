"""tests/live/env_guard.py 的 unit 測試（計畫 §3.1.1；§12.8 修正 3、4、15、16、17）。

每個檢查都有會被拒絕的正向對照。docker 以記錄參數、依情境回應的替身取代（不連 daemon）。
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
    check_config,
    check_environment,
    check_images,
    check_unresolved,
    compare,
    engine,
    live_session_problems,
    preflight,
    snapshot,
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
        "--filter",
        "label=com.docker.compose.project=secscan-live",
    ] in docker.calls


def test_preflight_refuses_a_leftover_secrets_directory(tmp_path: Path) -> None:
    (tmp_path / "secscan-live-secrets.abc123").mkdir()

    with pytest.raises(GuardError, match="拋棄式目錄"):
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


# --------------------------------------------------------------------------- snapshot


def _dev_docker() -> FakeDocker:
    return FakeDocker(
        {
            ("ps",): "c1\n",
            ("inspect",): "/secscan-db-1 c1 2026-11-07T00:00:00Z\n",
            ("volume", "ls"): "secscan_db_data\nsecscan_live_runs\nother\n",
            ("volume", "inspect"): "secscan_db_data 2026-11-01\n",
            ("network", "ls"): "secscan_scan_net n1\nbridge n0\nsecscan_default n2\n",
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
    assert taken["networks"] == ["secscan_default n2", "secscan_scan_net n1"]
    assert set(taken["files"]) == {".env", "secrets/db_password"}
    assert "never-printed" not in json.dumps(taken)


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


# --------------------------------------------------------------------------- Live 的 pytest


def _live_environment(tmp_path: Path, **changes: str | None) -> dict[str, str]:
    environ = {
        "SECSCAN_LIVE_PROJECT": "secscan-live",
        "SECSCAN_LIVE_SECRETS_DIR": str(tmp_path / "secscan-live-secrets.abc123"),
        "PATH": "/bin",
    }
    for key, value in changes.items():
        if value is None:
            environ.pop(key, None)
        else:
            environ[key] = value
    return environ


def test_the_live_session_environment_passes(tmp_path: Path) -> None:
    assert live_session_problems(_live_environment(tmp_path)) == []


@pytest.mark.parametrize(
    ("changes", "problem"),
    [
        ({"SECSCAN_LIVE_PROJECT": "secscan"}, "SECSCAN_LIVE_PROJECT"),
        ({"SECSCAN_LIVE_PROJECT": None}, "SECSCAN_LIVE_PROJECT"),
        ({"SECSCAN_LIVE_SECRETS_DIR": "/Users/someone/secrets"}, "SECSCAN_LIVE_SECRETS_DIR"),
        ({"SECSCAN_LIVE_SECRETS_DIR": None}, "SECSCAN_LIVE_SECRETS_DIR"),
        ({"DB_PASSWORD": "x"}, "DB_PASSWORD"),
        ({"CONTENT_ENCRYPTION_KEYS_FILE": "/x"}, "CONTENT_ENCRYPTION_KEYS_FILE"),
    ],
    ids=["dev-project", "no-project", "secrets-elsewhere", "no-secrets", "secret", "secret-file"],
)
def test_a_live_session_with_the_wrong_environment_is_refused(
    tmp_path: Path, changes: dict[str, str | None], problem: str
) -> None:
    assert problem in live_session_problems(_live_environment(tmp_path, **changes))


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
    ]
    (tmp_path / "base").mkdir()
    for argv, stdin in runs:
        monkeypatch.setattr("sys.stdin", io.StringIO(stdin))
        assert env_guard.main(argv) == env_guard.EXIT_OK, argv
    snapshot_text = capsys.readouterr().out.splitlines()[2]
    monkeypatch.setattr("sys.stdin", io.StringIO(snapshot_text))
    assert env_guard.main(["compare", "--root", str(tmp_path)]) == env_guard.EXIT_OK
    (tmp_path / ".env").write_text("changed\n", encoding="utf-8")
    monkeypatch.setattr("sys.stdin", io.StringIO(snapshot_text))
    assert env_guard.main(["compare", "--root", str(tmp_path)]) == env_guard.EXIT_FAILURE


def test_invalid_json_input_is_refused(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    for stdin in ("", "[1]"):
        monkeypatch.setattr("sys.stdin", io.StringIO(stdin))
        assert env_guard.main(["check-unresolved"]) == env_guard.EXIT_FAILURE
    assert "JSON" in capsys.readouterr().err
