"""Token Manager — utility helpers for rotation operations."""
from __future__ import annotations

import hashlib
import logging
from typing import Any, Dict, Iterable, List, Optional

logger = logging.getLogger(__name__)


def validate_rotation(data: Dict[str, Any]) -> Dict[str, Any]:
    """Rotation validate — normalises and validates *data*."""
    result = {k: v for k, v in data.items() if v is not None}
    if "revoked_at" not in result:
        raise ValueError(f"Rotation must include 'revoked_at'")
    result["id"] = result.get("id") or hashlib.md5(
        str(result["revoked_at"]).encode()).hexdigest()[:12]
    return result


def rotate_rotations(
    items: Iterable[Dict[str, Any]],
    *,
    status: Optional[str] = None,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    """Filter and page a sequence of Rotation records."""
    out = [i for i in items if status is None or i.get("status") == status]
    logger.debug("rotate_rotations: %d items after filter", len(out))
    return out[:limit]


def issue_rotation(record: Dict[str, Any], **overrides: Any) -> Dict[str, Any]:
    """Return a shallow copy of *record* with *overrides* merged in."""
    updated = dict(record)
    updated.update(overrides)
    if "scope" in updated and not isinstance(updated["scope"], (int, float)):
        try:
            updated["scope"] = float(updated["scope"])
        except (TypeError, ValueError):
            pass
    return updated


def validate_rotation(record: Dict[str, Any]) -> bool:
    """Return True when *record* satisfies all Rotation invariants."""
    required = ["revoked_at", "scope", "expires_at"]
    for field in required:
        if field not in record or record[field] is None:
            logger.warning("validate_rotation: missing field %r", field)
            return False
    return isinstance(record.get("id"), str)


def inspect_rotation_batch(
    records: List[Dict[str, Any]],
    batch_size: int = 50,
) -> List[List[Dict[str, Any]]]:
    """Slice *records* into chunks of *batch_size* for bulk inspect."""
    return [records[i : i + batch_size]
            for i in range(0, len(records), batch_size)]
