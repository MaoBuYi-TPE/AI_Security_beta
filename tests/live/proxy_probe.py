"""在 runner 容器內執行（以 stdin 傳入）：逐一呼叫不該開放的 Docker API。

回報 socket-proxy 的狀態碼。

輸出一行 JSON（{名稱: 狀態碼或例外類別}）。建立容器的請求都帶 host bind，就算放行也不會啟動。
"""

import http.client
import json

RUN = "secscan-run-00000000-0000-4000-8000-0000000000aa"
CREATE = f"/v1.45/containers/create?name={RUN}"
DIGEST = "sha256:" + "0" * 64
BUSYBOX = "busybox:1.38.0@sha256:fd7dc98638c8e305f4dc34e979f1c0fdfdcaeb0fbf8fcff77ae834b6da3d7e6e"
REQUESTS: dict[str, tuple[str, str, object]] = {
    "version": ("GET", "/v1.45/version", None),
    "info": ("GET", "/v1.45/info", None),
    "list": ("GET", "/v1.45/containers/json", None),
    "inspect_other": ("GET", "/v1.45/containers/secscan-db-1/json", None),
    "stop_other": ("POST", "/v1.45/containers/secscan-db-1/stop", None),
    "delete_other": ("DELETE", "/v1.45/containers/secscan-api-1", None),
    "exec_create": ("POST", f"/v1.45/containers/{RUN}/exec", {"Cmd": ["id"]}),
    "exec_start": ("POST", "/v1.45/exec/abc/start", {}),
    "archive_put": ("PUT", f"/v1.45/containers/{RUN}/archive?path=/", None),
    "archive_get": ("GET", f"/v1.45/containers/{RUN}/archive?path=/", None),
    "logs": ("GET", f"/v1.45/containers/{RUN}/logs", None),
    "kill": ("POST", f"/v1.45/containers/{RUN}/kill", None),
    "pull": ("POST", "/v1.45/images/create?fromImage=alpine&tag=latest", None),
    "build": ("POST", "/v1.45/build", None),
    "network_create": ("POST", "/v1.45/networks/create", {"Name": "x"}),
    "network_connect": ("POST", "/v1.45/networks/bridge/connect", {"Container": "x"}),
    "volume_create": ("POST", "/v1.45/volumes/create", {"Name": "x"}),
    "volumes_list": ("GET", "/v1.45/volumes", None),
    "secrets": ("GET", "/v1.45/secrets", None),
    "swarm": ("GET", "/v1.45/swarm", None),
    "system_df": ("GET", "/v1.45/system/df", None),
    "plugins": ("GET", "/v1.45/plugins", None),
    "events": ("GET", "/v1.45/events", None),
    "bind_create": (
        "POST",
        CREATE,
        {"Image": "busybox:1.38.0", "HostConfig": {"Binds": ["/:/host"]}},
    ),
    "mount_bind_create": (
        "POST",
        CREATE,
        {
            "Image": "busybox:1.38.0",
            "HostConfig": {
                "Mounts": [{"Type": "bind", "Source": "/var/run/docker.sock", "Target": "/s"}]
            },
        },
    ),
    # 路徑穿越、編碼與重複的斜線（審查建議）：proxy 都不能放行到其他端點。
    "traversal_distribution": (
        "GET",
        f"/v1.45/images/x/../../distribution/e.x/y:t@{DIGEST}/json",
        None,
    ),
    "traversal_exec": ("GET", f"/v1.45/images/a/../../exec/abc:t@{DIGEST}/json", None),
    "traversal_container": ("GET", f"/v1.45/containers/{RUN}/../secscan-db-1/json", None),
    "encoded_traversal": ("GET", f"/v1.45/images/{BUSYBOX}/json/%2e%2e/%2e%2e/info", None),
    "double_slash": ("GET", "/v1.45//info", None),
    "unapproved_image": ("GET", f"/v1.45/images/busybox:1.38.0@{DIGEST}/json", None),
    "volumes_from_create": (
        "POST",
        CREATE,
        {"Image": "busybox:1.38.0", "HostConfig": {"VolumesFrom": ["secscan-runner-1"]}},
    ),
}


def call(method: str, path: str, body: object) -> int | str:
    try:
        connection = http.client.HTTPConnection("socket-proxy", 2375, timeout=10)
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Content-Type": "application/json"} if data is not None else {}
        connection.request(method, path, body=data, headers=headers)
        return connection.getresponse().status
    except OSError as error:
        return type(error).__name__


print(json.dumps({label: call(*request) for label, request in REQUESTS.items()}))  # noqa: T201
