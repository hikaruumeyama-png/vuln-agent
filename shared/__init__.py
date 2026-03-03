"""起票パイプライン共通モジュール。

使用例:
    from shared.ticket_pipeline import generate_ticket, TicketResult
"""

from shared.ticket_pipeline import TicketResult, generate_ticket

__all__ = ["generate_ticket", "TicketResult"]
