"""lease 的 fencing（docs/DECISIONS.md §13.5）：只有仍持有、還沒過期的 lease 才能改變 run。"""

from sqlalchemy import ColumnElement, func

from secscan.scans.domain.model import Lease
from secscan.scans.models import ScannerRunModel


class LeaseLostError(Exception):
    """lease 已過期，或不屬於這個 owner：不能再改變這個 run（fencing）。"""


def holds(lease: Lease) -> tuple[ColumnElement[bool], ...]:
    """lease 仍屬於這個 owner、而且還沒過期（以 DB 的實際時間判斷）。"""
    return (
        ScannerRunModel.id == lease.run_id,
        ScannerRunModel.scan_id == lease.scan_id,
        ScannerRunModel.lease_owner == lease.owner,
        ScannerRunModel.lease_expires_at > func.clock_timestamp(),
    )
