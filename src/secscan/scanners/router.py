"""GET /scanners（docs/API_CONTRACT.md §2、docs/DECISIONS.md §14.7）。只做呼叫 service。"""

from fastapi import APIRouter

from secscan.api_keys.dependencies import CurrentPrincipal
from secscan.core.db import DbSession
from secscan.core.envelope import Envelope, ok
from secscan.scanners.schemas import ScannersOut
from secscan.scanners.service import ScannerCatalog

router = APIRouter(prefix="/scanners", tags=["scanners"])


@router.get("")
def list_scanners(_principal: CurrentPrincipal, session: DbSession) -> Envelope[ScannersOut]:
    """各引擎是否已整合、是否可用（依最近存活的 runner 回報的能力），以及 runner、worker 是否存活。

    任何有效的平台 key 都可以讀：內容不分 project，也不含秘密或路徑。
    """
    return ok(ScannersOut.of(ScannerCatalog(session).describe()))
