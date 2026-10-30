"""live 測試的 policy 觀察者（唯讀掛載 guard 的 policy volume 的容器內執行）。

每 1 ms 讀一次某個 run 的 policy，狀態改變時輸出一行 JSON：容器內的時間（VM 的時鐘，和 docker events
同一個）與狀態（active、blocked、absent）。只輸出狀態，不輸出 token 的雜湊或範圍。

stdin 是 JSON：{"run_id": "<uuid>", "seconds": 秒}。
"""

import json
import os
import sys
import time


def _state(path: str) -> str:
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
    except FileNotFoundError:
        return "absent"
    except OSError:
        return "unreadable"
    try:
        return str(json.loads(raw)["state"])
    except (ValueError, KeyError, TypeError):
        return "invalid"


def main() -> None:
    request = json.load(sys.stdin)
    path = os.path.join("/policies", f"{request['run_id']}.json")
    deadline = time.time() + float(request["seconds"])
    previous = None
    while time.time() < deadline:
        state = _state(path)
        if state != previous:
            sys.stdout.write(json.dumps({"t": time.time(), "state": state}) + "\n")
            sys.stdout.flush()
            previous = state
        time.sleep(0.001)


if __name__ == "__main__":
    main()
