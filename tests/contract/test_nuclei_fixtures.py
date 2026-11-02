"""Nuclei 的凍結模板與 JSONL parser 契約（T18；docs/DECISIONS.md §19.2、§23）。

不連網、不碰 Docker 與 DB：
- vendored 的 42 個模板和 lock 逐檔一致（sha256、數量、沒有多餘的檔）：runner 掛載前靠這份。
- load_template_files() 會逐檔驗 sha256，回傳 InputFile 用的（名稱, 內容）。
- 真實錄下的 nuclei JSONL（tests/fixtures/nuclei/）會解析成乾淨的成功並產出觀察。
"""

import hashlib
import json
from ipaddress import IPv4Address
from pathlib import Path

import pytest

from secscan.grants.domain.matching import ScopeRules
from secscan.grants.domain.scope import HttpMethod, Scope
from secscan.scanners.domain.nuclei import policy as nuclei_policy
from secscan.scanners.domain.nuclei.results import NucleiOutput, interpret
from secscan.scans.domain.lifecycle import RunStatus
from secscan.targets.domain import parse_origin

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "nuclei"
TEMPLATES_DIR = Path(nuclei_policy.__file__).with_name("templates")
GOLDEN = ["nuclei-juice-shop.jsonl", "nuclei-vampi-vuln.jsonl"]


def test_vendored_templates_match_the_lock_exactly() -> None:
    templates = nuclei_policy.load_templates()
    for template in templates:
        path = TEMPLATES_DIR / template.path
        assert path.is_file(), template.path
        assert hashlib.sha256(path.read_bytes()).hexdigest() == template.sha256, template.path
    # 沒有多餘的 .yaml（只掛凍結的檔）。
    on_disk = {p.relative_to(TEMPLATES_DIR).as_posix() for p in TEMPLATES_DIR.rglob("*.yaml")}
    assert on_disk == {template.path for template in templates}


def test_load_template_files_verifies_and_returns_every_template() -> None:
    files = nuclei_policy.load_template_files()
    templates = nuclei_policy.load_templates()
    assert len(files) == len(templates) == 42
    assert {name for name, _ in files} == {f"{t.id}.yaml" for t in templates}
    by_id = {t.id: t.sha256 for t in templates}
    for name, content in files:
        assert hashlib.sha256(content).hexdigest() == by_id[name.removesuffix(".yaml")]


@pytest.mark.parametrize("name", GOLDEN)
def test_real_golden_output_parses_to_a_clean_success(name: str) -> None:
    report = (FIXTURES / name).read_bytes()
    first = json.loads(report.splitlines()[0])
    origin = parse_origin(f"{first['scheme']}://{first['host']}:{first['port']}")
    output = NucleiOutput(
        exit_code=0,
        report=report,
        report_listed=True,
        origin=origin,
        rules=ScopeRules.of(
            Scope(
                origins=(origin,),
                ips=(IPv4Address("10.89.10.210"),),
                paths=(),
                allow_all_paths=True,
                excluded_paths=(),
                methods=(HttpMethod.GET, HttpMethod.HEAD, HttpMethod.POST),
            )
        ),
        forwarded=None,
        exchanges=None,
    )
    parsed = interpret(output)
    assert parsed.outcome.status is RunStatus.SUCCEEDED
    assert parsed.observations
    assert all(obs.source_rule in nuclei_policy.INCLUDE_TEMPLATE_IDS for obs in parsed.observations)
