"""T31：依實驗規格經平台 API 跑完排程，保存 manifest 與 guard 計數（make bench；DECISIONS §29）。

需要 BENCH_SPEC（實驗規格）與 BENCH_NAME（benchmarks/results/ 底下新的結果目錄，已存在就失敗）；
make bench 以環境變數傳入（不經 shell 文字）。流程：

1. 讀規格、排程（種子決定順序）；獨占建立結果目錄，複製規格。
2. 等 runner 的 probe 通過；每個（組別, 靶場）一個 project，同一個靶場用同一個 host。
3. 依排程：重建靶機 → 經 API 建立 scan → 等結束 → 停止靶機 → 經 API 收集並寫入檔案；
   比較區塊的 current 結束之後建立比較快照並收集。
4. 結構斷言：不是 fake、每個容器 run 都有 guard 計數、分到的等於 min（剩下的, 上限）、轉送數不超過
   分到的、guard 只看到靶機。不斷言偵測數（smoke 的數字不是實驗結果）。
5. 不論成功或失敗都寫 manifest（失敗時 complete 是 false）與 SHA256SUMS；不自動重試。
每個結果檔都以 bench 的金鑰（BENCH_KEY_FILE，預設 ~/.config/secscan/bench-keys）加密寫入，磁碟上
沒有明文（docs/DECISIONS.md §30.7）；make bench-check 在啟動 stack 之前先確認金鑰檔。

全部在同一個 pytest session 中完成：make test-live-runner 結束時 down -v 會清掉 DB。
"""

import hashlib
import os
import time
from pathlib import Path
from typing import Any

import pytest

from benchmarks.batch import (
    SPEC_FILE,
    comparison_document,
    comparison_file,
    labeled_scan,
    scan_document,
    scan_file,
)
from benchmarks.collect import collect_comparison, collect_scan, normalize_comparison
from benchmarks.manifest import MANIFEST_FILE, build_manifest
from benchmarks.models import ComparisonRecord, FileDigests, LabeledScan
from benchmarks.results import reserve, write_bytes, write_checksums, write_json
from benchmarks.schedule import ScheduledScan, build_schedule
from benchmarks.sealing import BenchKeys, key_file_path
from benchmarks.spec import ExperimentSpec, check_name, parse_spec
from tests.live.bench_support import (
    Placement,
    assert_allotments,
    create_comparison,
    create_scan,
    fetcher,
    grant_validity,
    guard_hosts_since,
    place,
    provenance,
    require_lab_images,
    session_hosts,
    start_target,
    wait_finished,
    wait_for_engines,
)
from tests.live.lab_support import stop_target
from tests.live.support import Api, admin_key

pytestmark = [pytest.mark.live, pytest.mark.enable_socket]
RESULTS_ROOT = Path(__file__).resolve().parents[2] / "benchmarks" / "results"


class Session:
    """一次 make bench：已寫入的檔案、收集到的 scan 與比較快照，以及這次建立的秘密。"""

    def __init__(self, spec: ExperimentSpec, digest: str, directory: Path, keys: BenchKeys) -> None:
        self.spec = spec
        self.digest = digest
        self.directory = directory
        self.keys = keys
        self.schedule = build_schedule(spec)
        self.files: dict[str, FileDigests] = {}
        self.scans: list[LabeledScan] = []
        self.comparisons: list[tuple[str, ComparisonRecord]] = []
        self.secrets: list[str] = []
        self.provenance: dict[str, Any] = {}
        self.placements: dict[tuple[str, str], Placement] = {}

    def write(self, name: str, document: object) -> None:
        self.files[name] = write_json(
            self.directory, name, document, keys=self.keys, known=self.secrets
        )

    def finish(self, *, complete: bool, stopped_reason: str | None) -> None:
        manifest = build_manifest(
            spec=self.spec,
            spec_sha256=self.digest,
            schedule=self.schedule,
            scans=self.scans,
            comparisons=self.comparisons,
            provenance=self.provenance,
            files=self.files,
            complete=complete,
            stopped_reason=stopped_reason,
        )
        write_json(self.directory, MANIFEST_FILE, manifest, keys=self.keys, known=self.secrets)
        write_checksums(self.directory)


def _required(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        pytest.fail(f"需要設定 {name}（以 make bench 執行）")
    return value


@pytest.fixture(scope="module")
def session() -> Session:
    # 規格只讀一次：解析、sha256 與複本都來自同一份位元組。
    content = Path(_required("BENCH_SPEC")).read_bytes()
    spec = parse_spec(content)
    keys = BenchKeys.load(key_file_path())
    directory = reserve(RESULTS_ROOT, check_name(_required("BENCH_NAME")))
    current = Session(spec, hashlib.sha256(content).hexdigest(), directory, keys)
    current.files[SPEC_FILE] = write_bytes(directory, SPEC_FILE, content, keys=keys)
    return current


def test_the_schedule_runs_through_the_api(session: Session) -> None:
    try:
        _run(session)
    except BaseException as error:
        # 不寫例外的訊息（可能含回應的內容）：只記種類，細節看 pytest 的輸出。
        session.finish(complete=False, stopped_reason=type(error).__name__)
        raise
    session.finish(complete=True, stopped_reason=None)


def _run(session: Session) -> None:
    spec = session.spec
    require_lab_images([target.kind for target in spec.targets])
    admin = Api(admin_key())
    session.secrets.append(admin.key)
    engines = sorted({engine for group in spec.groups for engine in group.engines})
    scanners = wait_for_engines(admin, engines)
    hosts = session_hosts(spec)
    session.provenance = provenance(admin, scanners=scanners, hosts=hosts)
    baselines: dict[str, LabeledScan] = {}
    for item in session.schedule:
        labeled = _scan(session, admin, item, hosts[item.target])
        session.scans.append(labeled)
        if item.role == "baseline" and item.comparison is not None:
            baselines[item.comparison] = labeled
        elif item.role == "current" and item.comparison is not None:
            _compare(session, item, baselines.pop(item.comparison), labeled)
        print(  # noqa: T201
            f"[bench] {item.position}/{len(session.schedule)} {item.group} {item.target} "
            f"{item.variant.value}：{labeled.scan.status}"
        )


def _scan(session: Session, admin: Api, item: ScheduledScan, host: str) -> LabeledScan:
    spec = session.spec
    kind = spec.target(item.target).kind
    target = start_target(kind, item.variant, host)
    try:
        key = (item.group, item.target)
        if key not in session.placements:
            session.placements[key] = place(
                admin, group=item.group, target=target, valid_for=grant_validity(spec)
            )
            session.secrets.append(session.placements[key].operator.key)
        placement = session.placements[key]
        started = time.time()
        scan_id = create_scan(placement, spec, spec.group(item.group))
        wait_finished(placement.operator, scan_id, budget_seconds=spec.budget.max_duration_seconds)
        seen = guard_hosts_since(started)
    finally:
        stop_target(target)
    assert seen <= {(target.host, target.port)}, seen
    scan, findings, observations = collect_scan(fetcher(placement.operator), scan_id)
    document = scan_document(
        item, target_kind=kind.value, scan=scan, findings=findings, observation_count=observations
    )
    labeled = labeled_scan(document)
    session.write(scan_file(item.position), document)
    _assert_structure(session, labeled)
    return labeled


def _assert_structure(session: Session, labeled: LabeledScan) -> None:
    scan = labeled.scan
    group = session.spec.group(labeled.group)
    assert not scan.fixture
    assert [run.engine for run in scan.runs] == list(group.engines)
    shares: dict[str, tuple[int, int]] = {
        share.engine: (share.max_requests, share.max_duration_seconds)
        for share in group.engine_budgets or ()
    }
    for run in scan.runs:
        expected = shares.get(run.engine)
        actual = (run.cap.max_requests, run.cap.max_duration_seconds) if run.cap else None
        assert actual == expected, run
    assert_allotments(scan)


def _compare(
    session: Session, item: ScheduledScan, baseline: LabeledScan, current: LabeledScan
) -> None:
    assert item.comparison is not None
    placement = session.placements[(item.group, item.target)]
    comparison_id = create_comparison(placement.operator, baseline.scan.id, current.scan.id)
    snapshot, findings = collect_comparison(fetcher(placement.operator), comparison_id)
    record = normalize_comparison(snapshot, findings)
    assert (record.baseline_scan_id, record.current_scan_id) == (baseline.scan.id, current.scan.id)
    session.write(
        comparison_file(item.comparison), comparison_document(item.comparison, snapshot, findings)
    )
    session.comparisons.append((item.comparison, record))
