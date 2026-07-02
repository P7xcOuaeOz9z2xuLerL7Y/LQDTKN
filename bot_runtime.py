import os
from typing import Optional


def smoke_limit(default: Optional[int] = None) -> Optional[int]:
    raw = os.environ.get("BOT_SMOKE_LIMIT", "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError("BOT_SMOKE_LIMIT must be a positive integer") from exc
    if value <= 0:
        raise ValueError("BOT_SMOKE_LIMIT must be a positive integer")
    return value


def batch_limit(default: int) -> int:
    limit = smoke_limit()
    return limit if limit is not None else default


def smoke_enabled() -> bool:
    return smoke_limit() is not None
