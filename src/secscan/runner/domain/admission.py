"""ExecutionPlan 的驗證與建立容器的 body（SEC-12、SEC-21；docs/DECISIONS.md §14.3、§14.4）。

1. admit()：plan 必須符合引擎的政策（核准的映像、指令樣板、環境變數、輸入檔、上限）。
2. container_spec()：由 plan 與固定的容器政策組出 Docker create 的 body。
3. check_container_spec()：送出之前，以獨立的規則再檢查一次 body（縱深防禦：組 body 的程式寫錯，
   或之後有人加了欄位，也不會送出 privileged、host bind、其他網路之類的設定）。

被拒絕時拋 PlanRejectedError：只有原因代碼，不含被拒絕的值（可能是工具參數或秘密）。
"""

from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from uuid import UUID

from secscan.core.identifiers import canonical_uuid
from secscan.core.json_types import JsonObject, JsonValue
from secscan.runner.domain.policy import ENGINE_POLICIES, ContainerPolicy, EnginePolicy
from secscan.scanners.domain.plan import ExecutionPlan
from secscan.scans.domain.catalog import Engine
from secscan.scans.domain.model import CONTAINER_NAME_PREFIX

# 掃描容器內的固定路徑：in/ 唯讀、out/ 可寫、secret 唯讀。
IN_DIR = "/scan/in"
OUT_DIR = "/scan/out"
# 以下是路徑與檔名，不是密碼。secret 目錄一律掛載：每個容器都有 proxy-url（egress guard 的帳密，
# docs/DECISIONS.md §15.4）；target-auth 只在 scan 有認證時才有。
SECRET_DIR = "/scan/secret"  # noqa: S105
SECRET_FILE = "target-auth"  # noqa: S105
PROXY_FILE = "proxy-url"
# 送出 secret 的那一行 header（preflight 用；docs/DECISIONS.md §16.5）。
AUTH_HEADER_FILE = "auth-header"
SECRET_FILES = frozenset({SECRET_FILE, PROXY_FILE, AUTH_HEADER_FILE})
# 容器的 log 由 Docker 保存：限制大小，工具大量輸出也不會塞滿磁碟。
LOG_CONFIG: JsonObject = {"Type": "json-file", "Config": {"max-size": "1m", "max-file": "1"}}
NOFILE_LIMIT = 1024
LABEL_PREFIX = "secscan."

_TOP_LEVEL_KEYS = frozenset({"Image", "Entrypoint", "Cmd", "Env", "User", "Labels", "HostConfig"})
_HOST_CONFIG_KEYS = frozenset(
    {
        "NetworkMode",
        "Mounts",
        "ReadonlyRootfs",
        "CapDrop",
        "SecurityOpt",
        "Privileged",
        "Init",
        "Memory",
        "MemorySwap",
        "NanoCpus",
        "PidsLimit",
        "Ulimits",
        "LogConfig",
        "RestartPolicy",
        "AutoRemove",
        "IpcMode",
        "CgroupnsMode",
    }
)
_MOUNT_KEYS = frozenset({"Type", "Source", "Target", "ReadOnly", "VolumeOptions"})
_FIXED_HOST_CONFIG: Mapping[str, JsonValue] = MappingProxyType(
    {
        "ReadonlyRootfs": True,
        "CapDrop": ["ALL"],
        "SecurityOpt": ["no-new-privileges:true"],
        "Privileged": False,
        "Init": True,
        "Ulimits": [{"Name": "nofile", "Soft": NOFILE_LIMIT, "Hard": NOFILE_LIMIT}],
        "LogConfig": LOG_CONFIG,
        "RestartPolicy": {"Name": "no"},
        "AutoRemove": False,
        # 明確指定，不依賴 daemon 的預設值（審查建議）。
        "IpcMode": "private",
        "CgroupnsMode": "private",
    }
)
# 送出前的檢查用自己的一份（刻意重複，不引用上面組 body 用的常數）：組 body 的程式或常數被改錯，
# 檢查不會跟著一起放行（審查發現）。改動時兩邊都要改，test_container_spec.py 會核對。
_REQUIRED_HOST_CONFIG: Mapping[str, JsonValue] = MappingProxyType(
    {
        "ReadonlyRootfs": True,
        "CapDrop": ["ALL"],
        "SecurityOpt": ["no-new-privileges:true"],
        "Privileged": False,
        "Init": True,
        "Ulimits": [{"Name": "nofile", "Soft": 1024, "Hard": 1024}],
        "LogConfig": {"Type": "json-file", "Config": {"max-size": "1m", "max-file": "1"}},
        "RestartPolicy": {"Name": "no"},
        "AutoRemove": False,
        "IpcMode": "private",
        "CgroupnsMode": "private",
    }
)


class PlanRejection(StrEnum):
    ENGINE_NOT_ALLOWED = "ENGINE_NOT_ALLOWED"
    IMAGE_NOT_APPROVED = "IMAGE_NOT_APPROVED"
    COMMAND_NOT_ALLOWED = "COMMAND_NOT_ALLOWED"
    ENVIRONMENT_NOT_ALLOWED = "ENVIRONMENT_NOT_ALLOWED"
    INPUT_NOT_ALLOWED = "INPUT_NOT_ALLOWED"
    TARGET_AUTH_NOT_ALLOWED = "TARGET_AUTH_NOT_ALLOWED"
    LIMITS_OUT_OF_RANGE = "LIMITS_OUT_OF_RANGE"
    UNSAFE_CONTAINER = "UNSAFE_CONTAINER"


class PlanRejectedError(Exception):
    def __init__(self, reason: PlanRejection) -> None:
        super().__init__(f"ExecutionPlan 被拒絕：{reason.value}")
        self.reason = reason


@dataclass(frozen=True, slots=True)
class ContainerSpec:
    name: str
    body: JsonObject


def container_name(run_id: UUID) -> str:
    return f"{CONTAINER_NAME_PREFIX}{run_id}"


def admit(plan: ExecutionPlan, policies: Mapping[Engine, EnginePolicy] = ENGINE_POLICIES) -> None:
    policy = policies.get(plan.engine)
    if policy is None:
        raise PlanRejectedError(PlanRejection.ENGINE_NOT_ALLOWED)
    if str(plan.image) not in policy.images:
        raise PlanRejectedError(PlanRejection.IMAGE_NOT_APPROVED)
    if not any(template.matches(plan.entrypoint, plan.arguments) for template in policy.commands):
        raise PlanRejectedError(PlanRejection.COMMAND_NOT_ALLOWED)
    if not _environment_allowed(plan.environment, policy):
        raise PlanRejectedError(PlanRejection.ENVIRONMENT_NOT_ALLOWED)
    if not _inputs_allowed(plan, policy):
        raise PlanRejectedError(PlanRejection.INPUT_NOT_ALLOWED)
    if plan.target_auth and not policy.accepts_target_auth:
        raise PlanRejectedError(PlanRejection.TARGET_AUTH_NOT_ALLOWED)
    limits, caps = plan.limits, policy.max_limits
    if not (
        limits.memory_bytes <= caps.memory_bytes
        and limits.nano_cpus <= caps.nano_cpus
        and limits.pids <= caps.pids
        and limits.wall_clock_seconds <= caps.wall_clock_seconds
    ):
        raise PlanRejectedError(PlanRejection.LIMITS_OUT_OF_RANGE)


def _environment_allowed(environment: tuple[tuple[str, str], ...], policy: EnginePolicy) -> bool:
    names = [name for name, _ in environment]
    if len(set(names)) != len(names):
        return False
    return all(
        name in policy.environment and policy.environment[name].accepts(value)
        for name, value in environment
    )


def _inputs_allowed(plan: ExecutionPlan, policy: EnginePolicy) -> bool:
    names = Counter(item.name for item in plan.inputs)
    return all(count == 1 and name in policy.input_names for name, count in names.items()) and all(
        len(item.content) <= policy.max_input_bytes for item in plan.inputs
    )


def container_spec(plan: ExecutionPlan, policy: ContainerPolicy) -> ContainerSpec:
    """由 plan 與容器政策組出 create 的 body（呼叫端先以 admit 驗證過 plan）。"""
    limits = plan.limits
    host_config: JsonObject = {
        "NetworkMode": policy.scan_network,
        "Mounts": _mounts(plan, policy),
        "Memory": limits.memory_bytes,
        "MemorySwap": limits.memory_bytes,
        "NanoCpus": limits.nano_cpus,
        "PidsLimit": limits.pids,
        **_FIXED_HOST_CONFIG,
    }
    body: JsonObject = {
        "Image": str(plan.image),
        "Entrypoint": list(plan.entrypoint),
        "Cmd": list(plan.arguments),
        "Env": [f"{name}={value}" for name, value in plan.environment],
        "User": policy.user,
        "Labels": dict(_labels(plan)),
        "HostConfig": host_config,
    }
    return ContainerSpec(name=container_name(plan.run_id), body=body)


def build_container(
    plan: ExecutionPlan,
    *,
    policy: ContainerPolicy,
    engines: Mapping[Engine, EnginePolicy] = ENGINE_POLICIES,
) -> ContainerSpec:
    admit(plan, engines)
    spec = container_spec(plan, policy)
    check_container_spec(spec, plan=plan, policy=policy)
    return spec


def check_container_spec(
    spec: ContainerSpec, *, plan: ExecutionPlan, policy: ContainerPolicy
) -> None:
    """獨立於 container_spec 的檢查：任何一項不符就拒絕。"""
    if not _safe(spec, plan, policy):
        raise PlanRejectedError(PlanRejection.UNSAFE_CONTAINER)


def _safe(spec: ContainerSpec, plan: ExecutionPlan, policy: ContainerPolicy) -> bool:
    body = spec.body
    host = body.get("HostConfig")
    if not isinstance(host, dict):
        return False
    return (
        spec.name == container_name(plan.run_id)
        and set(body) == _TOP_LEVEL_KEYS
        and set(host) == _HOST_CONFIG_KEYS
        and body["Image"] == str(plan.image)
        and body["Entrypoint"] == list(plan.entrypoint)
        and body["Cmd"] == list(plan.arguments)
        and body["Env"] == [f"{name}={value}" for name, value in plan.environment]
        and body["User"] == policy.user
        and _non_root(policy.user)
        and body["Labels"] == dict(_labels(plan))
        and all(host[key] == value for key, value in _REQUIRED_HOST_CONFIG.items())
        and host["NetworkMode"] == policy.scan_network
        and _bounded(host)
        and _mounts_safe(host["Mounts"], plan, policy)
    )


def _non_root(user: str) -> bool:
    uid, separator, gid = user.partition(":")
    return bool(separator) and all(
        part.isascii() and part.isdigit() and int(part) > 0 for part in (uid, gid)
    )


def _bounded(host: JsonObject) -> bool:
    memory, swap = host["Memory"], host["MemorySwap"]
    values = (memory, host["NanoCpus"], host["PidsLimit"])
    return all(type(value) is int and value > 0 for value in values) and swap == memory


def _mounts_safe(mounts: JsonValue, plan: ExecutionPlan, policy: ContainerPolicy) -> bool:
    """只能是這個 run 的 volume subpath：in/ 與 secret 唯讀、out/ 可寫，順序固定。

    不呼叫組 body 用的 _mounts：各自寫一次，任一邊寫錯都會被另一邊擋下。
    """
    run = str(plan.run_id)
    allowed = [
        ("/scan/in", policy.runs_volume, f"{run}/in", True),
        ("/scan/out", policy.runs_volume, f"{run}/out", False),
        ("/scan/secret", policy.secrets_volume, run, True),
    ]
    if not isinstance(mounts, list) or len(mounts) != len(allowed):
        return False
    return all(
        isinstance(mount, dict)
        and set(mount) == _MOUNT_KEYS
        and mount["Type"] == "volume"
        and (mount["Target"], mount["Source"], mount["ReadOnly"]) == (target, source, read_only)
        and mount["VolumeOptions"] == {"Subpath": subpath, "NoCopy": True}
        for mount, (target, source, subpath, read_only) in zip(mounts, allowed, strict=True)
    )


def _mounts(plan: ExecutionPlan, policy: ContainerPolicy) -> list[JsonValue]:
    run = str(plan.run_id)
    return [
        _volume(policy.runs_volume, f"{run}/in", IN_DIR, read_only=True),
        _volume(policy.runs_volume, f"{run}/out", OUT_DIR, read_only=False),
        _volume(policy.secrets_volume, run, SECRET_DIR, read_only=True),
    ]


def _volume(source: str, subpath: str, target: str, *, read_only: bool) -> JsonObject:
    # NoCopy：不把映像中該路徑的內容複製進 volume（子目錄由 runner 建立）。
    return {
        "Type": "volume",
        "Source": source,
        "Target": target,
        "ReadOnly": read_only,
        "VolumeOptions": {"Subpath": subpath, "NoCopy": True},
    }


def managed_run_id(labels: Mapping[str, object]) -> UUID | None:
    """容器的 label 標示的 run（對帳核對容器是不是這個 run 的，docs/DECISIONS.md §17.2）。

    不是 runner 建立的（沒有 managed、run_id 不是標準格式的 UUID）就是 None。
    """
    if labels.get(f"{LABEL_PREFIX}managed") != "true":
        return None
    value = labels.get(f"{LABEL_PREFIX}run_id")
    return canonical_uuid(value) if isinstance(value, str) else None


def _labels(plan: ExecutionPlan) -> Mapping[str, str]:
    """容器的對帳以 label 核對這個 run 的容器（managed_run_id）。"""
    return {
        f"{LABEL_PREFIX}managed": "true",
        f"{LABEL_PREFIX}run_id": str(plan.run_id),
        f"{LABEL_PREFIX}scan_id": str(plan.scan_id),
        f"{LABEL_PREFIX}engine": plan.engine.value,
    }
