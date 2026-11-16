"""tests/live/env_guard.py 的 unit 測試（計畫 §3.1.1；§12.8 修正 3、4、15、16、17）。

每個檢查都有會被拒絕的正向對照。docker 以記錄參數、依情境回應的替身取代（不連 daemon）。
"""

import io
import json
import os
import shutil
import stat
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
    cleanup,
    compare,
    engine,
    live_session_problems,
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


def _network_docker(**facts: str) -> FakeDocker:
    docker = FakeDocker()
    for spec in LIVE_SPECS:
        reply = facts.get(spec.name, f"true|isolated|{spec.subnet} {spec.ip_range}|{OWNER}\n")
        key = ("network", "inspect", "--format", env_guard.NETWORK_FORMAT, spec.name)
        docker.replies[key] = reply
    return docker


def test_the_networks_are_created_internal_isolated_and_labelled_with_the_run() -> None:
    docker = _network_docker()

    claim_networks(docker, LIVE_SPECS, OWNER)

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


def test_an_existing_network_is_never_shared() -> None:
    """並行：network create 是原子的；已存在（另一次 Live 的）就停止，不檢查、不沿用。"""
    docker = _network_docker()
    docker.replies[("network", "create")] = "<fail>"

    with pytest.raises(GuardError, match="另一次 Live"):
        claim_networks(docker, LIVE_SPECS, OWNER)

    assert [call[:2] for call in docker.calls] == [["network", "create"]]


@pytest.mark.parametrize(
    ("facts", "message"),
    [
        (
            {"secscan_live_lab_net": f"false|isolated|10.89.10.0/24 10.89.10.0/25|{OWNER}\n"},
            "internal",
        ),
        ({"secscan_live_scan_net": f"true|nat|10.89.9.0/24 10.89.9.0/25|{OWNER}\n"}, "isolated"),
        ({"secscan_live_scan_net": f"true|isolated|10.89.9.0/24 |{OWNER}\n"}, "ip-range"),
        ({"secscan_live_scan_net": "true|isolated|10.89.9.0/24 10.89.9.0/25|other\n"}, "這次執行"),
        ({"secscan_live_lab_net": "true\n"}, "無法確認"),
    ],
    ids=["not-internal", "gateway", "no-ip-range", "other-owner", "unparsable"],
)
def test_networks_with_the_wrong_settings_are_refused(facts: dict[str, str], message: str) -> None:
    with pytest.raises(GuardError, match=message):
        claim_networks(_network_docker(**facts), LIVE_SPECS, OWNER)


@pytest.mark.parametrize(
    "names",
    [
        ("secscan_scan_net", "secscan_live_lab_net"),
        ("secscan_live_scan_net",),
        ("secscan_live_scan_net", "secscan_live_lab_net", "secscan_lab_net"),
    ],
    ids=["dev-network", "only-one", "extra"],
)
def test_only_the_two_live_networks_can_be_created(names: tuple[str, ...]) -> None:
    docker = _network_docker()

    with pytest.raises(GuardError, match="Live 的兩個網路"):
        claim_networks(
            docker, [NetworkSpec(name, "10.0.0.0/24", "10.0.0.0/25") for name in names], OWNER
        )

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


# --------------------------------------------------------------------------- cleanup

LIVE_CONFIG = {
    "name": "secscan-live",
    "volumes": {
        "db_data": {"name": "secscan-live_db_data"},
        "runs": {"name": "secscan_live_runs"},
    },
    "networks": {
        "scan_net": {"name": "secscan_live_scan_net", "external": True},
        "default": {"name": "secscan-live_default"},
    },
}


class LiveDocker:
    """有狀態的 docker 替身：網路與所有權的標記、容器（id、專案、網路）、volume。

    fail 列出的動作（例如 "down"、"network rm"）回傳失敗。
    """

    def __init__(
        self,
        *,
        networks: dict[str, str] | None = None,
        containers: list[dict[str, str]] | None = None,
        volumes: list[str] | None = None,
        config: object = None,
        fail: Sequence[str] = (),
    ) -> None:
        self.networks = (
            dict.fromkeys(env_guard.LIVE_NETWORKS, OWNER) if networks is None else dict(networks)
        )
        self.containers = list(containers or [])
        self.volumes = ["secscan-live_db_data", "secscan_live_runs"] if volumes is None else volumes
        self.config = LIVE_CONFIG if config is None else config
        self.fail = set(fail)
        self.calls: list[list[str]] = []

    def __call__(self, arguments: Sequence[str]) -> str:
        args = list(arguments)
        self.calls.append(args)
        action = "down" if args[:1] == ["compose"] and "down" in args else " ".join(args[:2])
        if action in self.fail or args[0] in self.fail:
            raise GuardError("docker 失敗")
        handler = {
            "network ls": lambda: "\n".join(self.networks) + "\n",
            "network inspect": lambda: (self.networks.get(args[-1]) or env_guard.NO_VALUE) + "\n",
            "network rm": lambda: self._pop_network(args[2]),
            "volume ls": lambda: "\n".join(self.volumes) + "\n",
            "down": self._down,
        }.get(action)
        if handler is not None:
            return handler()
        if args[0] == "ps":
            return "\n".join(self._containers(args[-1])) + "\n"
        if args[0] == "inspect":
            [found] = [c for c in self.containers if c["id"] == args[-1]]
            return (found["project"] or env_guard.NO_VALUE) + "\n"
        if args[0] == "rm":
            self.containers = [c for c in self.containers if c["id"] not in args]
            return ""
        if args[0] == "compose" and "config" in args:
            return self.config if isinstance(self.config, str) else json.dumps(self.config)
        raise AssertionError(f"沒有預期的 docker 呼叫：{args[:3]}")

    def _containers(self, selector: str) -> list[str]:
        if selector.startswith("network="):
            return [c["id"] for c in self.containers if c["network"] == selector[len("network=") :]]
        return [c["id"] for c in self.containers if c["project"] == "secscan-live"]

    def _pop_network(self, name: str) -> str:
        self.networks.pop(name)
        return ""

    def _down(self) -> str:
        self.containers = [c for c in self.containers if c["project"] != "secscan-live"]
        self.volumes = []
        return ""

    def destructive(self) -> list[list[str]]:
        return [
            call
            for call in self.calls
            if call[:1] == ["rm"] or call[:2] == ["network", "rm"] or "down" in call
        ]


def _run_dir(tmp_path: Path) -> Path:
    directory = tmp_path / OWNER
    directory.mkdir(mode=0o700)
    (directory / "db_password").write_text("disposable", encoding="ascii")
    return directory


def test_cleanup_without_a_directory_touches_nothing(tmp_path: Path) -> None:
    docker = LiveDocker()

    report = cleanup(docker, tmp_path, "")

    assert (report.failures, docker.calls) == ([], [])


def test_cleanup_refuses_a_directory_it_cannot_attribute(tmp_path: Path) -> None:
    other = tmp_path / "elsewhere" / OWNER
    other.mkdir(parents=True)
    docker = LiveDocker()

    report = cleanup(docker, tmp_path, str(other))

    assert report.failures
    assert docker.calls == []
    assert other.exists()


def test_an_owned_run_is_removed_completely(tmp_path: Path) -> None:
    directory = _run_dir(tmp_path)
    docker = LiveDocker(
        containers=[
            {"id": "c-receiver", "project": "", "network": "secscan_live_lab_net"},
            {"id": "c-api", "project": "secscan-live", "network": "secscan_live_scan_net"},
            {"id": "c-db", "project": "secscan-live", "network": "secscan-live_default"},
        ]
    )

    report = cleanup(docker, tmp_path, str(directory))

    assert report.failures == []
    assert docker.networks == {}
    assert docker.containers == []
    assert not directory.exists()
    assert [*env_guard.LIVE_COMPOSE, "down", "-v", "--remove-orphans"] in docker.calls
    assert ["rm", "-f", "-v", "c-receiver", "c-api"] in docker.calls


def test_networks_of_another_run_are_left_alone(tmp_path: Path) -> None:
    """並行：網路的標記是另一次執行的。只刪自己的拋棄式目錄，不 down、不刪容器與網路。"""
    directory = _run_dir(tmp_path)
    others = dict.fromkeys(env_guard.LIVE_NETWORKS, "secscan-live-secrets.Other1")
    docker = LiveDocker(
        networks=others,
        containers=[{"id": "c-api", "project": "secscan-live", "network": "secscan_live_scan_net"}],
    )

    report = cleanup(docker, tmp_path, str(directory))

    assert report.failures == []
    assert len(report.skipped) == len(env_guard.LIVE_NETWORKS)
    assert docker.destructive() == []
    assert docker.networks == others
    assert not directory.exists()


def test_a_partial_claim_removes_only_its_own_network(tmp_path: Path) -> None:
    directory = _run_dir(tmp_path)
    docker = LiveDocker(
        networks={"secscan_live_scan_net": OWNER, "secscan_live_lab_net": "<no value>"},
        containers=[{"id": "c-probe", "project": "", "network": "secscan_live_scan_net"}],
    )

    report = cleanup(docker, tmp_path, str(directory))

    assert report.failures == []
    assert docker.networks == {"secscan_live_lab_net": "<no value>"}
    assert not [call for call in docker.calls if "down" in call]


def test_containers_of_another_project_are_never_removed(tmp_path: Path) -> None:
    directory = _run_dir(tmp_path)
    docker = LiveDocker(
        containers=[
            {"id": "c-dev-runner", "project": "secscan", "network": "secscan_live_scan_net"},
            {"id": "c-probe", "project": "", "network": "secscan_live_scan_net"},
        ]
    )

    report = cleanup(docker, tmp_path, str(directory))

    assert ["rm", "-f", "-v", "c-probe"] in docker.calls
    assert "c-dev-runner" in {c["id"] for c in docker.containers}
    assert [failure for failure in report.failures if "c-dev-runner" in failure]


@pytest.mark.parametrize(
    ("changes", "volumes"),
    [
        ({"name": "secscan"}, None),
        ({"volumes": {"db_data": {"name": "secscan_db_data"}}}, None),
        ({"volumes": {"db_data": {"name": "secscan-live_db_data", "external": True}}}, None),
        ({"networks": {"scan_net": {"name": "secscan_scan_net"}}}, None),
        ({}, ["secscan_live_runs", "secscan_db_data"]),
    ],
    ids=["dev-project", "dev-volume", "external-volume", "dev-network", "existing-dev-volume"],
)
def test_down_runs_only_when_every_target_is_a_live_resource(
    tmp_path: Path, changes: dict[str, Any], volumes: list[str] | None
) -> None:
    """M2（HIGH）：down -v 之前核對專案、解析出來的 volume 與網路、既有的 volume。"""
    directory = _run_dir(tmp_path)
    docker = LiveDocker(config={**LIVE_CONFIG, **changes}, volumes=volumes)

    report = cleanup(docker, tmp_path, str(directory))

    assert not [call for call in docker.calls if "down" in call]
    assert [failure for failure in report.failures if "down -v" in failure]


@pytest.mark.parametrize(
    ("docker", "message"),
    [
        (LiveDocker(config="not json"), "down -v"),
        (LiveDocker(fail=["compose"]), "無法核對"),
        (LiveDocker(fail=["volume ls"]), "無法核對"),
        (LiveDocker(fail=["down"]), "compose down -v"),
        (LiveDocker(fail=["network rm"]), "還有網路"),
        (
            LiveDocker(
                fail=["rm"],
                containers=[{"id": "c1", "project": "", "network": "secscan_live_lab_net"}],
            ),
            "刪除 Live 網路上的容器",
        ),
        (LiveDocker(fail=["ps"]), "列出網路"),
        (LiveDocker(fail=["network ls"]), "列出網路"),
        (LiveDocker(fail=["network inspect"]), "所有權"),
    ],
    ids=[
        "config-not-json",
        "config-fails",
        "volumes-fail",
        "down-fails",
        "network-rm-fails",
        "rm-fails",
        "ps-fails",
        "network-ls-fails",
        "inspect-fails",
    ],
)
def test_every_failed_step_is_reported(tmp_path: Path, docker: LiveDocker, message: str) -> None:
    """MEDIUM-2：清理失敗不能被忽略。"""
    directory = _run_dir(tmp_path)

    report = cleanup(docker, tmp_path, str(directory))

    assert [failure for failure in report.failures if message in failure], report.failures


def test_a_failed_down_reports_the_remaining_resources(tmp_path: Path) -> None:
    directory = _run_dir(tmp_path)
    docker = LiveDocker(
        fail=["down"],
        containers=[{"id": "c-db", "project": "secscan-live", "network": "secscan-live_default"}],
    )

    report = cleanup(docker, tmp_path, str(directory))

    assert [failure for failure in report.failures if "容器（1 個）" in failure]
    assert [failure for failure in report.failures if "volume（2 個）" in failure]


def test_a_symlinked_directory_is_not_followed(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "keep").write_text("keep", encoding="ascii")
    (tmp_path / OWNER).symlink_to(target)

    report = cleanup(LiveDocker(), tmp_path, str(tmp_path / OWNER))

    assert [failure for failure in report.failures if "自己擁有的目錄" in failure]
    assert (target / "keep").exists()


def test_a_directory_that_cannot_be_removed_is_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory = _run_dir(tmp_path)

    def refuse(_path: object) -> None:
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(shutil, "rmtree", refuse)

    report = cleanup(LiveDocker(), tmp_path, str(directory))

    assert [failure for failure in report.failures if "無法刪除拋棄式目錄" in failure]
    assert [failure for failure in report.failures if "拋棄式目錄還在" in failure]


def test_an_already_removed_directory_is_fine(tmp_path: Path) -> None:
    report = cleanup(LiveDocker(), tmp_path, str(tmp_path / OWNER))

    assert report.failures == []


def test_the_diagnostic_lists_steps_and_names_only(tmp_path: Path) -> None:
    path = write_diagnostic(tmp_path, str(tmp_path / OWNER), ["compose down -v", "刪除網路 x"])

    text = path.read_text(encoding="utf-8")
    assert path.name.startswith(env_guard.DIAGNOSTIC_PREFIX)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert OWNER in text
    assert "- compose down -v" in text


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
        (
            [
                "networks",
                *("--secrets-dir", f"/srv/{OWNER}"),
                *("--network", "secscan_live_scan_net", "10.89.9.0/24", "10.89.9.0/25"),
                *("--network", "secscan_live_lab_net", "10.89.10.0/24", "10.89.10.0/25"),
            ],
            "",
        ),
    ]
    docker.replies.update(_network_docker().replies)
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


def test_the_cleanup_cli_reports_success_and_what_it_left_alone(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    directory = _run_dir(tmp_path)
    networks = {
        "secscan_live_scan_net": OWNER,
        "secscan_live_lab_net": "secscan-live-secrets.Other1",
    }
    monkeypatch.setattr(env_guard, "docker", LiveDocker(networks=networks))

    code = env_guard.main(["cleanup", "--base", str(tmp_path), "--secrets-dir", str(directory)])

    out = capsys.readouterr().out
    assert code == env_guard.EXIT_OK
    assert out.startswith("cleanup ok")
    assert "secscan_live_lab_net" in out
    assert list(tmp_path.glob(f"{env_guard.DIAGNOSTIC_PREFIX}*")) == []


def test_the_cleanup_cli_fails_and_keeps_a_diagnostic(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    directory = _run_dir(tmp_path)
    monkeypatch.setattr(env_guard, "docker", LiveDocker(fail=["down"]))

    code = env_guard.main(["cleanup", "--base", str(tmp_path), "--secrets-dir", str(directory)])

    err = capsys.readouterr().err
    [diagnostic] = tmp_path.glob(f"{env_guard.DIAGNOSTIC_PREFIX}*")
    assert code == env_guard.EXIT_FAILURE
    assert "清理沒有完成" in err
    assert str(diagnostic) in err
    assert "compose down -v" in diagnostic.read_text(encoding="utf-8")


def test_the_cleanup_cli_still_fails_when_the_diagnostic_cannot_be_written(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    monkeypatch.setattr(env_guard, "docker", LiveDocker(fail=["network ls"]))
    base = tmp_path / "gone"

    code = env_guard.main(["cleanup", "--base", str(base), "--secrets-dir", str(base / OWNER)])

    assert code == env_guard.EXIT_FAILURE
    assert "無法寫入診斷檔" in capsys.readouterr().err


def test_invalid_json_input_is_refused(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    for stdin in ("", "[1]"):
        monkeypatch.setattr("sys.stdin", io.StringIO(stdin))
        assert env_guard.main(["check-unresolved"]) == env_guard.EXIT_FAILURE
    assert "JSON" in capsys.readouterr().err
