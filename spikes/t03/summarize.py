"""彙整 guard JSONL slice：請求數、決策分布、方法、上游 IP、帶 Authorization 數。

用法：python -I summarize.py <guard.jsonl> [host]
host 省略時彙整全部；給了就只算該 host。輸出給 TOOLS.md 的可重現素材。
"""

from __future__ import annotations

import collections
import json
import sys


def main(argv: list[str]) -> int:
    path = argv[0]
    host_filter = argv[1] if len(argv) > 1 else None
    decisions: collections.Counter[str] = collections.Counter()
    methods: collections.Counter[str] = collections.Counter()
    upstreams: set[str] = set()
    total = 0
    with_auth = 0
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            if "GUARDLOG" not in line:
                continue
            record = json.loads(line.split(" ", 1)[1])
            if host_filter and record["host"] != host_filter:
                continue
            total += 1
            decisions[record["decision"]] += 1
            methods[record["method"]] += 1
            if record.get("upstream"):
                upstreams.add(record["upstream"][0])
            if record.get("has_authorization"):
                with_auth += 1
    summary = {
        "total": total,
        "decisions": dict(decisions),
        "methods": dict(methods),
        "upstream_ips": sorted(upstreams),
        "with_authorization": with_auth,
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
