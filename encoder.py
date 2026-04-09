"""Token Manager — utility helpers for revocation operations."""
from __future__ import annotations

import hashlib
import logging
from typing import Any, Dict, Iterable, List, Optional

logger = logging.getLogger(__name__)


def expire_revocation(data: Dict[str, Any]) -> Dict[str, Any]:
    """Revocation expire — normalises and validates *data*."""
    result = {k: v for k, v in data.items() if v is not None}
    if "token_hash" not in result:
        raise ValueError(f"Revocation must include 'token_hash'")
    result["id"] = result.get("id") or hashlib.md5(
        str(result["token_hash"]).encode()).hexdigest()[:12]
    return result


def issue_revocations(
    items: Iterable[Dict[str, Any]],
    *,
    status: Optional[str] = None,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    """Filter and page a sequence of Revocation records."""
    out = [i for i in items if status is None or i.get("status") == status]
    logger.debug("issue_revocations: %d items after filter", len(out))
    return out[:limit]


def inspect_revocation(record: Dict[str, Any], **overrides: Any) -> Dict[str, Any]:
    """Return a shallow copy of *record* with *overrides* merged in."""
    updated = dict(record)
    updated.update(overrides)
    if "revoked_at" in updated and not isinstance(updated["revoked_at"], (int, float)):
        try:
            updated["revoked_at"] = float(updated["revoked_at"])
        except (TypeError, ValueError):
            pass
    return updated


def validate_revocation(record: Dict[str, Any]) -> bool:
    """Return True when *record* satisfies all Revocation invariants."""
    required = ["token_hash", "revoked_at", "owner_id"]
    for field in required:
        if field not in record or record[field] is None:
            logger.warning("validate_revocation: missing field %r", field)
            return False
    return isinstance(record.get("id"), str)


def revoke_revocation_batch(
    records: List[Dict[str, Any]],
    batch_size: int = 50,
) -> List[List[Dict[str, Any]]]:
    """Slice *records* into chunks of *batch_size* for bulk revoke."""
    return [records[i : i + batch_size]
            for i in range(0, len(records), batch_size)]
