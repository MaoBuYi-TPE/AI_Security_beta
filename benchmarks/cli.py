"""benchmark 的離線指令（make bench-check、make bench-evaluate；docs/DECISIONS.md §29）。

- check-spec：檢查實驗規格與結果目錄的名稱（不合或已存在就失敗）；make bench 在啟動 stack 之前
  先跑，不連網、不碰 Docker。
- evaluate：只讀結果目錄（先核對 SHA256SUMS 與 manifest，session 必須完整），評估結果以 canonical
  JSON 寫到 stdout，不寫回結果目錄。
"""

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from benchmarks.batch import load_batch
from benchmarks.evaluate import evaluate
from benchmarks.ground_truth import load_adjudications, load_ground_truth, load_pair_labels
from benchmarks.results import canonical_json
from benchmarks.schedule import build_schedule
from benchmarks.spec import check_name, load_spec
from benchmarks.stats import evaluation_json

DEFAULT_RESULTS = Path(__file__).resolve().parent / "results"
FAILURE = 2


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "check-spec":
            output = _check_spec(arguments.spec, arguments.name, arguments.results_root)
        else:
            output = _evaluate(arguments)
    except (OSError, ValueError) as error:
        sys.stderr.write(f"bench: {error}\n")
        return FAILURE
    sys.stdout.write(output)
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m benchmarks.cli")
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser("check-spec", help="檢查實驗規格與結果目錄的名稱")
    check.add_argument("spec", type=Path)
    check.add_argument("name")
    check.add_argument("--results-root", type=Path, default=DEFAULT_RESULTS)
    scoring = commands.add_parser("evaluate", help="評估一個完整的結果目錄（只讀）")
    scoring.add_argument("name")
    scoring.add_argument("--results-root", type=Path, default=DEFAULT_RESULTS)
    scoring.add_argument("--truth", type=Path, action="append", default=[])
    scoring.add_argument("--adjudications", type=Path)
    scoring.add_argument("--pair-labels", type=Path)
    scoring.add_argument("--include-holdout", action="store_true")
    return parser


def _check_spec(path: Path, name: str, root: Path) -> str:
    spec, digest = load_spec(path)
    check_name(name)
    if (root / name).exists():
        raise ValueError("結果目錄已經存在；請換一個新的 BENCH_NAME")
    schedule = build_schedule(spec)
    return (
        f"{spec.name}（{spec.purpose.value}）：{len(schedule)} 個 scan，種子 {spec.seed}，"
        f"規格 sha256 {digest}\n"
    )


def _evaluate(arguments: argparse.Namespace) -> str:
    name = check_name(arguments.name)
    batch = load_batch(arguments.results_root / name)
    inputs: dict[str, Any] = {"ground_truth": {}, "adjudications": None, "pair_labels": None}
    truths = []
    for path in arguments.truth:
        truth, digest = load_ground_truth(path)
        truths.append(truth)
        inputs["ground_truth"][truth.target.value] = digest
    adjudications = pair_labels = None
    if arguments.adjudications is not None:
        adjudications, inputs["adjudications"] = load_adjudications(arguments.adjudications)
    if arguments.pair_labels is not None:
        pair_labels, inputs["pair_labels"] = load_pair_labels(arguments.pair_labels)
    result = evaluate(
        batch.scans,
        truths=truths,
        adjudications=adjudications,
        pair_labels=pair_labels,
        comparisons=batch.comparisons,
        include_holdout=arguments.include_holdout,
    )
    document = {
        "name": name,
        "spec_sha256": batch.manifest["spec_sha256"],
        "inputs": inputs,
        **evaluation_json(result, purpose=str(batch.manifest["purpose"])),
    }
    return canonical_json(document).decode("utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
