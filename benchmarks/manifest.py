"""run manifest（SECURITY_AND_TESTING.md §8；docs/DECISIONS.md §29）。

記錄重現與稽核需要的：規格的 sha256、種子與實際順序；程式、映像、profile 與靶機的身分；每個 scan 的
預算、子預算、狀態與 guard 計數；每個檔案明文與密文的 sha256（版本 2，T23a 起結果檔都加密；
docs/DECISIONS.md §30.7）；session 是否完整。API 拿不到的身分（commit、
本機建置的映像、fixture 的原始碼雜湊、strict-1 的 path 規則）由 harness 記下並標明來源。
"""

import re
from collections.abc import Mapping, Sequence
from typing import Any

from benchmarks.models import ComparisonRecord, FileDigests, LabeledScan, RunRecord
from benchmarks.schedule import ScheduledScan
from benchmarks.spec import ExperimentSpec

MANIFEST_VERSION = 2
MANIFEST_FILE = "manifest.json"
_SHA256 = re.compile(r"[0-9a-f]{64}")
REQUIRED_PROVENANCE = ("git_commit", "git_dirty", "scanners", "scan_profiles", "targets")
# 一律揭露的限制（docs/DECISIONS.md §29）。
DISCLOSURES = (
    # 結果檔以本機的 bench 金鑰加密（不是平台的金鑰）；金鑰遺失之後無法復原。
    "results_encrypted_with_local_bench_key",
    "bench_key_loss_makes_results_unrecoverable",
    "observation_evidence_not_stored",
    "path_policy_strict_1_identified_by_commit",
    "engine_order_fixed_zap_then_nuclei",
    "unused_engine_share_is_forfeited",
    "cleanup_seconds_reduce_later_allotments",
    "nuclei_stopped_by_the_runner_yields_no_output",
)
_REQUIRED = (
    "manifest_version",
    "name",
    "purpose",
    "spec_sha256",
    "seed",
    "budget",
    "groups",
    "schedule",
    "scans",
    "comparisons",
    "provenance",
    "files",
    "complete",
    "stopped_reason",
    "disclosures",
)


class ManifestError(ValueError):
    """manifest 缺少欄位，或 session 沒有完整結束。"""


def build_manifest(
    *,
    spec: ExperimentSpec,
    spec_sha256: str,
    schedule: Sequence[ScheduledScan],
    scans: Sequence[LabeledScan],
    comparisons: Sequence[tuple[str, ComparisonRecord]],
    provenance: Mapping[str, object],
    files: Mapping[str, FileDigests],
    complete: bool,
    stopped_reason: str | None,
) -> dict[str, Any]:
    if complete and (stopped_reason is not None or len(scans) != len(schedule)):
        raise ManifestError("完整的 session 必須跑完排程中的每個 scan")
    return {
        "manifest_version": MANIFEST_VERSION,
        "name": spec.name,
        "purpose": spec.purpose.value,
        "spec_sha256": spec_sha256,
        "seed": spec.seed,
        "budget": spec.budget.model_dump(mode="json"),
        "groups": [group.model_dump(mode="json") for group in spec.groups],
        "schedule": [_scheduled(item) for item in schedule],
        "scans": [_scan(item) for item in scans],
        "comparisons": [
            {
                "comparison": block,
                "id": record.id,
                "baseline_scan_id": record.baseline_scan_id,
                "current_scan_id": record.current_scan_id,
                "comparability": record.comparability,
                "manual_review_required": record.manual_review_required,
                "items": len(record.items),
            }
            for block, record in comparisons
        ],
        "provenance": dict(provenance),
        "files": {
            name: {"sha256": digests.sha256, "sealed_sha256": digests.sealed_sha256}
            for name, digests in sorted(files.items())
        },
        "complete": complete,
        "stopped_reason": stopped_reason,
        "disclosures": list(DISCLOSURES),
    }


def check_manifest(manifest: object, *, require_complete: bool = True) -> dict[str, Any]:
    """評估之前的檢查：欄位齊全、版本相符、session 完整。"""
    if not isinstance(manifest, dict):
        raise ManifestError("manifest 必須是物件")
    missing = [key for key in _REQUIRED if key not in manifest]
    if missing:
        raise ManifestError(f"manifest 缺少欄位：{'、'.join(missing)}")
    if manifest["manifest_version"] != MANIFEST_VERSION:
        raise ManifestError("manifest 的版本不符")
    provenance = manifest["provenance"]
    if not isinstance(provenance, dict) or any(
        key not in provenance for key in REQUIRED_PROVENANCE
    ):
        raise ManifestError("manifest 的 provenance 不完整")
    files = manifest["files"]
    if not isinstance(files, dict) or not all(_digests(entry) for entry in files.values()):
        raise ManifestError("manifest 的 files 必須記下每個檔案明文與密文的 sha256")
    if require_complete and manifest["complete"] is not True:
        raise ManifestError("session 沒有完整結束（complete 是 false），不評估：整批作廢")
    return manifest


def _digests(entry: object) -> bool:
    return (
        isinstance(entry, dict)
        and entry.keys() == {"sha256", "sealed_sha256"}
        and all(isinstance(value, str) and _SHA256.fullmatch(value) for value in entry.values())
    )


def _scheduled(item: ScheduledScan) -> dict[str, Any]:
    return {
        "position": item.position,
        "unit": item.unit,
        "group": item.group,
        "target": item.target,
        "variant": item.variant.value,
        "repetition": item.repetition,
        "comparison": item.comparison,
        "role": item.role,
    }


def _scan(item: LabeledScan) -> dict[str, Any]:
    scan = item.scan
    return {
        "position": item.position,
        "scan_id": scan.id,
        "group": item.group,
        "target": item.target,
        "target_kind": item.target_kind,
        "variant": item.variant,
        "repetition": item.repetition,
        "comparison": item.comparison,
        "role": item.role,
        "status": scan.status,
        "budget": {
            "requests_per_second": scan.requests_per_second,
            "max_requests": scan.max_requests,
            "max_duration_seconds": scan.max_duration_seconds,
        },
        "runs": [_run(run) for run in scan.runs],
        "findings": len(scan.findings),
        "observations": scan.observation_count,
        "created_at": scan.created_at,
        "finished_at": scan.finished_at,
    }


def _run(run: RunRecord) -> dict[str, Any]:
    return {
        "engine": run.engine,
        "status": run.status,
        "error_code": run.error_code,
        "plan_hash": run.plan_hash,
        "cap": (
            {
                "max_requests": run.cap.max_requests,
                "max_duration_seconds": run.cap.max_duration_seconds,
            }
            if run.cap is not None
            else None
        ),
        "requests_allotted": run.requests_allotted,
        "seconds_allotted": run.seconds_allotted,
        "requests_sent": run.requests_sent,
        "requests_denied": run.requests_denied,
        "traffic_seconds": run.traffic_seconds,
    }
