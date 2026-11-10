"""結果目錄的檔案配置：Live 的 harness 寫入、make bench-evaluate 讀回（同一份程式）。

- spec.yaml：規格檔的原樣複本（sha256 等於 manifest 的 spec_sha256）。
- scan-NNN.json：排程的位置、標籤與 API 回的原始 JSON（scan、這個 scan 的 finding、觀察數）。
  評估時再以 benchmarks.collect 正規化，和 Live 收集時走同一段程式。
- comparison-<id>.json：比較快照與它的 finding。
- manifest.json、SHA256SUMS。
T23a 起每個檔案都加密成 `<檔名>.sealed`（docs/DECISIONS.md §30.7）：讀回時先核對 SHA256SUMS
（密文），再解密、核對 manifest 記下的明文 sha256。
"""

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from benchmarks.collect import CollectError, normalize_comparison, normalize_scan
from benchmarks.manifest import MANIFEST_FILE, check_manifest
from benchmarks.models import ComparisonRecord, LabeledScan
from benchmarks.results import read_bytes, read_json, sealed_name, verify
from benchmarks.schedule import ScheduledScan
from benchmarks.sealing import BenchKeys

SPEC_FILE = "spec.yaml"


@dataclass(frozen=True, slots=True)
class Batch:
    manifest: Mapping[str, Any]
    scans: tuple[LabeledScan, ...]
    comparisons: tuple[tuple[str, ComparisonRecord], ...]


def scan_file(position: int) -> str:
    return f"scan-{position:03d}.json"


def comparison_file(block: str) -> str:
    return f"comparison-{block}.json"


def scan_document(
    item: ScheduledScan,
    *,
    target_kind: str,
    scan: Mapping[str, Any],
    findings: Sequence[Mapping[str, Any]],
    observation_count: int,
) -> dict[str, Any]:
    return {
        "labels": {
            "position": item.position,
            "group": item.group,
            "target": item.target,
            "target_kind": target_kind,
            "variant": item.variant.value,
            "repetition": item.repetition,
            "comparison": item.comparison,
            "role": item.role,
        },
        "scan": dict(scan),
        "findings": [dict(finding) for finding in findings],
        "observation_count": observation_count,
    }


def comparison_document(
    block: str, snapshot: Mapping[str, Any], findings: Sequence[Mapping[str, Any]]
) -> dict[str, Any]:
    return {
        "comparison": block,
        "snapshot": dict(snapshot),
        "findings": [dict(f) for f in findings],
    }


def labeled_scan(document: Mapping[str, Any]) -> LabeledScan:
    labels = document.get("labels")
    if not isinstance(labels, dict):
        raise CollectError("scan 檔缺少 labels")
    findings = document.get("findings")
    if not isinstance(findings, list):
        raise CollectError("scan 檔的 findings 必須是陣列")
    scan = document.get("scan")
    if not isinstance(scan, dict):
        raise CollectError("scan 檔缺少 scan")
    count = document.get("observation_count")
    if isinstance(count, bool) or not isinstance(count, int):
        raise CollectError("scan 檔的 observation_count 必須是整數")
    record = normalize_scan(scan, findings, count)
    return LabeledScan(
        position=labels["position"],
        group=labels["group"],
        target=labels["target"],
        target_kind=labels["target_kind"],
        variant=labels["variant"],
        repetition=labels["repetition"],
        comparison=labels["comparison"],
        role=labels["role"],
        scan=record,
    )


def load_batch(directory: Path, keys: BenchKeys) -> Batch:
    """核對 SHA256SUMS 與 manifest（session 必須完整），再解密、核對並讀回每個 scan 與比較快照。"""
    checksums = verify(directory)
    manifest = check_manifest(read_json(directory, MANIFEST_FILE, keys=keys))
    files: Mapping[str, Mapping[str, str]] = manifest["files"]

    def opened(name: str) -> bytes:
        expected = files.get(name)
        if expected is None or expected["sealed_sha256"] != checksums.get(sealed_name(name)):
            raise CollectError(f"{name} 和 manifest 不符")
        content = read_bytes(directory, name, keys=keys)
        if hashlib.sha256(content).hexdigest() != expected["sha256"]:
            raise CollectError(f"{name} 解密之後和 manifest 的 sha256 不符")
        return content

    spec_digest = hashlib.sha256(opened(SPEC_FILE)).hexdigest()
    if spec_digest != manifest["spec_sha256"]:
        raise CollectError("spec.yaml 和 manifest 的 sha256 不符")
    scans = []
    for entry in manifest["scans"]:
        item = labeled_scan(json.loads(opened(scan_file(entry["position"]))))
        if (item.position, item.scan.id) != (entry["position"], entry["scan_id"]):
            raise CollectError("scan 檔和 manifest 不符")
        scans.append(item)
    comparisons = []
    for entry in manifest["comparisons"]:
        document = json.loads(opened(comparison_file(entry["comparison"])))
        record = normalize_comparison(document["snapshot"], document["findings"])
        if record.id != entry["id"]:
            raise CollectError("比較檔和 manifest 不符")
        comparisons.append((str(entry["comparison"]), record))
    return Batch(manifest=manifest, scans=tuple(scans), comparisons=tuple(comparisons))
