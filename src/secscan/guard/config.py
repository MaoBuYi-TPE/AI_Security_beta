"""guard 的設定與 mitmproxy 的 options（docs/DECISIONS.md §15.1、§15.2、§15.6）。

環境變數（compose 給定）：
- LAB_CIDR、GUARD_SCAN_CIDR：lab_net 與 scan_net 的網段（都要符合 LAB_CIDR 的規則、互不重疊）。
- GUARD_LAB_IP、GUARD_SCAN_IP：guard 在兩個網段上的位址，必須是各自的最後一個主機位址
  （在 --ip-range 之外，動態配發不會給別的容器）。
- GUARD_POLICIES_DIR、GUARD_STATUS_DIR、GUARD_TELEMETRY_DIR、GUARD_CONFDIR：絕對路徑（有預設值）。

options 分兩批：核心的在建立 Options 時給定，addon 的要等 DumpMaster 載入預設 addon 之後才能設定；
設定之後逐一讀回核對（option_problems），不符就不啟動。
"""

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path

from secscan.core.network import lab_cidr_problem
from secscan.targets.domain import LabNetwork, parse_ipv4

GUARD_PORT = 8080
BODY_SIZE_LIMIT = "16m"
DEFAULT_POLICIES_DIR = Path("/guard/policies")
DEFAULT_STATUS_DIR = Path("/guard/status")
DEFAULT_TELEMETRY_DIR = Path("/guard/telemetry")
# mitmproxy 在 confdir 建立 CA 檔（P0 不用）：放在 tmpfs 的 /tmp。映像宣告的 VOLUME
# （/home/mitmproxy/.mitmproxy）在 0700、屬於 mitmproxy 使用者的目錄下，uid 10001 進不去。
DEFAULT_CONFDIR = Path("/tmp/mitmproxy")  # noqa: S108 - guard 容器自己的 tmpfs，只有 10001 可寫
_REQUIRED = ("LAB_CIDR", "GUARD_SCAN_CIDR", "GUARD_SCAN_IP", "GUARD_LAB_IP")


class GuardConfigError(ValueError):
    """設定不合規則。訊息只有變數名稱與原因。"""


@dataclass(frozen=True, slots=True)
class GuardConfig:
    lab: LabNetwork
    scan_network: IPv4Network
    scan_ip: IPv4Address
    lab_ip: IPv4Address
    policies_dir: Path = DEFAULT_POLICIES_DIR
    status_dir: Path = DEFAULT_STATUS_DIR
    telemetry_dir: Path = DEFAULT_TELEMETRY_DIR
    confdir: Path = DEFAULT_CONFDIR

    def __post_init__(self) -> None:
        for name, network in (("LAB_CIDR", self.lab.cidr), ("GUARD_SCAN_CIDR", self.scan_network)):
            problem = lab_cidr_problem(network)
            if problem is not None:
                raise GuardConfigError(f"{name}：{problem.removeprefix('LAB_CIDR ')}")
        if self.lab.cidr.overlaps(self.scan_network):
            raise GuardConfigError("GUARD_SCAN_CIDR 不可和 LAB_CIDR 重疊")
        if self.lab_ip != self.lab.guard_address:
            raise GuardConfigError("GUARD_LAB_IP 必須是 LAB_CIDR 的最後一個主機位址")
        if self.scan_ip != self.scan_network.broadcast_address - 1:
            raise GuardConfigError("GUARD_SCAN_IP 必須是 GUARD_SCAN_CIDR 的最後一個主機位址")
        directories = (self.policies_dir, self.status_dir, self.telemetry_dir, self.confdir)
        if not all(directory.is_absolute() for directory in directories):
            raise GuardConfigError("guard 的目錄必須是絕對路徑")
        if len(set(directories)) != len(directories):
            raise GuardConfigError("policy、status、telemetry 與 confdir 必須是不同的目錄")

    @property
    def listen(self) -> str:
        return f"{self.scan_ip}:{GUARD_PORT}"

    @property
    def guard_ips(self) -> frozenset[IPv4Address]:
        return frozenset({self.scan_ip, self.lab_ip})


def config_from_env(env: Mapping[str, str]) -> GuardConfig:
    missing = [name for name in _REQUIRED if name not in env]
    if missing:
        raise GuardConfigError(f"缺少環境變數：{'、'.join(missing)}")
    return GuardConfig(
        lab=LabNetwork(_network(env, "LAB_CIDR")),
        scan_network=_network(env, "GUARD_SCAN_CIDR"),
        scan_ip=_address(env, "GUARD_SCAN_IP"),
        lab_ip=_address(env, "GUARD_LAB_IP"),
        policies_dir=Path(env.get("GUARD_POLICIES_DIR", str(DEFAULT_POLICIES_DIR))),
        status_dir=Path(env.get("GUARD_STATUS_DIR", str(DEFAULT_STATUS_DIR))),
        telemetry_dir=Path(env.get("GUARD_TELEMETRY_DIR", str(DEFAULT_TELEMETRY_DIR))),
        confdir=Path(env.get("GUARD_CONFDIR", str(DEFAULT_CONFDIR))),
    )


def _network(env: Mapping[str, str], name: str) -> IPv4Network:
    value = env[name]
    try:
        network = IPv4Network(value)
    except ValueError:
        raise GuardConfigError(f"{name} 不是合法的 IPv4 網段（host bits 必須為 0）") from None
    if str(network) != value:
        raise GuardConfigError(f"{name} 必須是 canonical 寫法（例如 10.89.7.0/24）")
    return network


def _address(env: Mapping[str, str], name: str) -> IPv4Address:
    value = env[name]
    try:
        # parse_ipv4 只接受四段十進位、沒有前導 0 的寫法（本身就是 canonical）。
        return parse_ipv4(value)
    except ValueError:
        raise GuardConfigError(f"{name} 不是合法的 IPv4 位址（四段十進位）") from None


def core_options(config: GuardConfig) -> dict[str, object]:
    """建立 Options 時給定的核心 options（§15.2）。"""
    return {
        "confdir": str(config.confdir),
        # 只聽 scan 那一側：lab 那一側的靶機連不到 proxy。
        "mode": [f"regular@{config.listen}"],
        "upstream_cert": False,
        "http2": False,
        "http3": False,
        "websocket": False,
        "rawtcp": False,
        "ssl_insecure": False,
        # 非空時流量會不經 HTTP 層、也不經 addon 直接轉送。
        "ignore_hosts": [],
        "allow_hosts": [],
        "tcp_hosts": [],
        "udp_hosts": [],
    }


def addon_options() -> dict[str, object]:
    """DumpMaster 載入預設 addon 之後才能設定的 options（§15.2）。"""
    return {
        # eager 會在檢查之前就連上游（CONNECT 時）。
        "connection_strategy": "lazy",
        "body_size_limit": BODY_SIZE_LIMIT,
        # streaming 會在 request hook 之前就建立上游連線。
        "stream_large_bodies": None,
        "validate_inbound_headers": True,
        "normalize_outbound_headers": True,
        "onboarding": False,
        "command_history": False,
        "anticache": False,
        "anticomp": False,
        "block_global": True,
        "block_private": False,
        "map_remote": [],
        "map_local": [],
        "modify_headers": [],
        "modify_body": [],
        "block_list": [],
        "client_replay": [],
        "server_replay": [],
        "scripts": [],
        "proxyauth": None,
        "upstream_auth": None,
        "stickyauth": None,
        "stickycookie": None,
        "save_stream_file": None,
        "connect_addr": None,
        "rfile": None,
        "termlog_verbosity": "warn",
    }


def expected_options(config: GuardConfig) -> dict[str, object]:
    return {**core_options(config), **addon_options()}


def option_problems(
    read: Callable[[str], object], expected: Mapping[str, object]
) -> tuple[str, ...]:
    """讀回的值和預期不同（或讀不到）的 option 名稱；序列以內容比較。"""
    problems: list[str] = []
    for name, value in expected.items():
        try:
            actual = read(name)
        except (AttributeError, KeyError):
            problems.append(name)
            continue
        if _normalized(actual) != _normalized(value):
            problems.append(name)
    return tuple(problems)


def _normalized(value: object) -> object:
    if isinstance(value, (list, tuple)):
        return [_normalized(item) for item in value]
    return value
