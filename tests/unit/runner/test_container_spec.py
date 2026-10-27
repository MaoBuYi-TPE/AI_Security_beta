"""建立容器的 body 與不變式（SEC-21 的應用層、docs/DECISIONS.md §14.3、§14.4）。

body 由 plan 與固定的容器政策組成；送出之前再以獨立的規則檢查一次，任何危險的欄位都擋下。
"""

import copy
from collections.abc import Callable
from dataclasses import replace
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from secscan.runner.domain.admission import (
    ContainerSpec,
    PlanRejectedError,
    PlanRejection,
    build_container,
    check_container_spec,
    container_name,
    container_spec,
)
from secscan.scanners.domain.fake import MAX_HOLD_SECONDS, FakeOutcome, FakeScript
from tests.unit.runner.plans import POLICY, RUN_ID, SCAN_ID, fake_plan

PLAN = fake_plan()
AUTH_PLAN = fake_plan(target_auth=True)
type Body = dict[str, Any]


def _body(*, target_auth: bool = False) -> Body:
    spec = container_spec(AUTH_PLAN if target_auth else PLAN, POLICY)
    return copy.deepcopy(dict(spec.body))


def test_the_container_is_named_after_the_run() -> None:
    assert container_name(RUN_ID) == f"secscan-run-{RUN_ID}"
    assert container_spec(PLAN, POLICY).name == container_name(RUN_ID)


def test_the_body_is_hardened() -> None:
    body = _body()
    host = body["HostConfig"]

    assert body["Image"] == str(PLAN.image)
    assert (body["Entrypoint"], body["Cmd"]) == (["/bin/sleep"], ["5"])
    assert body["Env"] == []
    assert body["User"] == "10001:10001"
    assert body["Labels"] == {
        "secscan.managed": "true",
        "secscan.run_id": str(RUN_ID),
        "secscan.scan_id": str(SCAN_ID),
        "secscan.engine": "fake",
    }
    assert host["Privileged"] is False
    assert host["ReadonlyRootfs"] is True
    assert host["CapDrop"] == ["ALL"]
    assert host["SecurityOpt"] == ["no-new-privileges:true"]
    assert host["Init"] is True
    assert host["NetworkMode"] == "secscan_scan_net"
    assert host["Memory"] == host["MemorySwap"] == 64 * 1024 * 1024
    assert host["NanoCpus"] == 500_000_000
    assert host["PidsLimit"] == 64
    assert host["RestartPolicy"] == {"Name": "no"}
    assert host["AutoRemove"] is False
    assert "Binds" not in host


def test_only_the_run_directories_are_mounted() -> None:
    mounts = _body()["HostConfig"]["Mounts"]

    assert mounts == [
        {
            "Type": "volume",
            "Source": "secscan_runs",
            "Target": "/scan/in",
            "ReadOnly": True,
            "VolumeOptions": {"Subpath": f"{RUN_ID}/in", "NoCopy": True},
        },
        {
            "Type": "volume",
            "Source": "secscan_runs",
            "Target": "/scan/out",
            "ReadOnly": False,
            "VolumeOptions": {"Subpath": f"{RUN_ID}/out", "NoCopy": True},
        },
    ]


def test_the_secret_is_mounted_read_only_when_the_scan_authenticates() -> None:
    mounts = _body(target_auth=True)["HostConfig"]["Mounts"]

    assert mounts[-1] == {
        "Type": "volume",
        "Source": "secscan_run_secrets",
        "Target": "/scan/secret",
        "ReadOnly": True,
        "VolumeOptions": {"Subpath": str(RUN_ID), "NoCopy": True},
    }


@given(
    outcome=st.sampled_from(FakeOutcome),
    hold=st.floats(min_value=0, max_value=MAX_HOLD_SECONDS),
    target_auth=st.booleans(),
)
def test_every_built_container_passes_the_checks(
    outcome: FakeOutcome, hold: float, target_auth: bool
) -> None:
    plan = fake_plan(FakeScript(outcome=outcome, hold_seconds=hold), target_auth=target_auth)

    spec = build_container(plan, policy=POLICY)

    check_container_spec(spec, plan=plan, policy=POLICY)


def _set(path: str, value: object) -> Callable[[Body], None]:
    def change(body: Body) -> None:
        *parents, last = path.split(".")
        node = body
        for part in parents:
            node = node[part]
        node[last] = value

    return change


def _delete(path: str) -> Callable[[Body], None]:
    def change(body: Body) -> None:
        *parents, last = path.split(".")
        node = body
        for part in parents:
            node = node[part]
        del node[last]

    return change


def _mount(index: int, key: str, value: object) -> Callable[[Body], None]:
    def change(body: Body) -> None:
        body["HostConfig"]["Mounts"][index][key] = value

    return change


def _subpath(index: int, value: str) -> Callable[[Body], None]:
    def change(body: Body) -> None:
        body["HostConfig"]["Mounts"][index]["VolumeOptions"]["Subpath"] = value

    return change


def _add_mount(mount: dict[str, object]) -> Callable[[Body], None]:
    def change(body: Body) -> None:
        body["HostConfig"]["Mounts"].append(mount)

    return change


def _drop_mount(index: int) -> Callable[[Body], None]:
    def change(body: Body) -> None:
        del body["HostConfig"]["Mounts"][index]

    return change


_UNSAFE: dict[str, Callable[[Body], None]] = {
    "privileged": _set("HostConfig.Privileged", True),
    "binds": _set("HostConfig.Binds", ["/:/host"]),
    "cap_add": _set("HostConfig.CapAdd", ["SYS_ADMIN"]),
    "cap_drop_empty": _set("HostConfig.CapDrop", []),
    "security_opt_missing": _set("HostConfig.SecurityOpt", []),
    "seccomp_off": _set("HostConfig.SecurityOpt", ["no-new-privileges:true", "seccomp=unconfined"]),
    "writable_rootfs": _set("HostConfig.ReadonlyRootfs", False),
    "host_network": _set("HostConfig.NetworkMode", "host"),
    "other_network": _set("HostConfig.NetworkMode", "secscan_control_net"),
    "pid_host": _set("HostConfig.PidMode", "host"),
    "ipc_host": _set("HostConfig.IpcMode", "host"),
    "userns_host": _set("HostConfig.UsernsMode", "host"),
    "devices": _set("HostConfig.Devices", [{"PathOnHost": "/dev/kmsg"}]),
    "sysctls": _set("HostConfig.Sysctls", {"net.ipv4.ip_forward": "1"}),
    "extra_hosts": _set("HostConfig.ExtraHosts", ["db:10.0.0.2"]),
    "ports": _set("HostConfig.PortBindings", {"80/tcp": [{"HostPort": "80"}]}),
    "volumes_from": _set("HostConfig.VolumesFrom", ["secscan-api-1"]),
    "no_init": _set("HostConfig.Init", False),
    "auto_remove": _set("HostConfig.AutoRemove", True),
    "restart": _set("HostConfig.RestartPolicy", {"Name": "always"}),
    "no_memory": _delete("HostConfig.Memory"),
    "swap": _set("HostConfig.MemorySwap", -1),
    "no_cpus": _set("HostConfig.NanoCpus", 0),
    "no_pids": _set("HostConfig.PidsLimit", 0),
    "unbounded_pids": _set("HostConfig.PidsLimit", -1),
    "log_driver": _set("HostConfig.LogConfig", {"Type": "json-file", "Config": {}}),
    "root_user": _set("User", "0:0"),
    "named_root": _set("User", "root"),
    "user_missing": _delete("User"),
    "other_user": _set("User", "1000:1000"),
    "other_image": _set("Image", "busybox:latest"),
    "exposed_ports": _set("ExposedPorts", {"80/tcp": {}}),
    "anonymous_volume": _set("Volumes", {"/data": {}}),
    "hostname_spoof": _set("Hostname", "db"),
    "labels_changed": _set("Labels", {"secscan.managed": "true"}),
    "command_changed": _set("Cmd", ["/bin/sh"]),
    "env_injected": _set("Env", ["LD_PRELOAD=/scan/in/x.so"]),
    "bind_mount": _add_mount({"Type": "bind", "Source": "/", "Target": "/host"}),
    "other_volume": _mount(0, "Source", "secscan_db_data"),
    "other_run": _subpath(0, "00000000-0000-4000-8000-000000000000/in"),
    "traversal": _subpath(1, f"{RUN_ID}/../../x"),
    "volume_root": _subpath(0, ""),
    "writable_input": _mount(0, "ReadOnly", False),
    "other_target": _mount(1, "Target", "/etc"),
    "copy_on_mount": lambda body: body["HostConfig"]["Mounts"][0]["VolumeOptions"].update(
        NoCopy=False
    ),
    "secret_without_auth": _add_mount(
        {
            "Type": "volume",
            "Source": "secscan_run_secrets",
            "Target": "/scan/secret",
            "ReadOnly": True,
            "VolumeOptions": {"Subpath": str(RUN_ID), "NoCopy": True},
        }
    ),
    "duplicate_mount": lambda body: body["HostConfig"]["Mounts"].append(
        copy.deepcopy(body["HostConfig"]["Mounts"][0])
    ),
    "output_missing": _drop_mount(1),
    "mount_extra_key": _mount(0, "BindOptions", {"Propagation": "rshared"}),
    "tmpfs": _set("HostConfig.Tmpfs", {"/run": "exec"}),
    "cgroup_parent": _set("HostConfig.CgroupParent", "/"),
    "runtime": _set("HostConfig.Runtime", "runc-unsafe"),
    "host_config_not_an_object": _set("HostConfig", ["Privileged"]),
    "mounts_not_a_list": _set("HostConfig.Mounts", {"Type": "volume"}),
    "mount_not_an_object": lambda body: body["HostConfig"]["Mounts"].__setitem__(0, "volume"),
}


@pytest.mark.parametrize("name", sorted(_UNSAFE))
def test_unsafe_bodies_are_refused(name: str) -> None:
    body = _body()
    _UNSAFE[name](body)
    spec = ContainerSpec(name=container_name(RUN_ID), body=body)

    with pytest.raises(PlanRejectedError) as caught:
        check_container_spec(spec, plan=PLAN, policy=POLICY)

    assert caught.value.reason is PlanRejection.UNSAFE_CONTAINER


def test_the_secret_mount_is_required_when_the_scan_authenticates() -> None:
    body = _body(target_auth=True)
    del body["HostConfig"]["Mounts"][-1]
    spec = ContainerSpec(name=container_name(RUN_ID), body=body)

    with pytest.raises(PlanRejectedError):
        check_container_spec(spec, plan=AUTH_PLAN, policy=POLICY)


def test_the_name_must_match_the_run() -> None:
    spec = ContainerSpec(name="secscan-api-1", body=_body())

    with pytest.raises(PlanRejectedError):
        check_container_spec(spec, plan=PLAN, policy=POLICY)


def test_building_an_unadmitted_plan_fails_before_any_body() -> None:
    with pytest.raises(PlanRejectedError) as caught:
        build_container(replace(PLAN, arguments=("5", "6")), policy=POLICY)

    assert caught.value.reason is PlanRejection.COMMAND_NOT_ALLOWED
