"""脆弱性ソースアダプター群。"""

from .base import BaseSourceAdapter, fetch_with_retry, http_get_json
from .almalinux import AlmaLinuxAdapter
from .cisa_kev import CisaKevAdapter
from .cisco_csaf import CiscoCsafAdapter
from .fortinet import FortinetAdapter
from .jvn import JvnAdapter
from .motex import MotexAdapter
from .msrc import MsrcAdapter
from .nvd import NvdAdapter
from .osv import OsvAdapter
from .skysea import SkySEAAdapter
from .zabbix import ZabbixAdapter

ADAPTER_REGISTRY: dict[str, type[BaseSourceAdapter]] = {
    # Phase 1: 公開DB
    "cisa_kev": CisaKevAdapter,
    "nvd": NvdAdapter,
    # Phase 2: 公開DB (続き)
    "jvn": JvnAdapter,
    "osv": OsvAdapter,
    # Phase 3: ベンダー API
    "cisco_csaf": CiscoCsafAdapter,
    "msrc": MsrcAdapter,
    "fortinet": FortinetAdapter,
    "almalinux": AlmaLinuxAdapter,
    # Phase 4: スクレイピング (6時間間隔)
    "zabbix": ZabbixAdapter,
    "motex": MotexAdapter,
    "skysea": SkySEAAdapter,
}


def get_adapter(source_id: str) -> BaseSourceAdapter:
    """source_id からアダプターインスタンスを返す。"""
    cls = ADAPTER_REGISTRY.get(source_id)
    if cls is None:
        raise ValueError(f"Unknown source_id: {source_id}")
    return cls()
