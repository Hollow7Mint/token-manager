"""Token Manager — Audit repository layer."""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Iterator, List, Optional

logger = logging.getLogger(__name__)


class TokenRepository:
    """Audit repository for the Token Manager application."""

    def __init__(
        self,
        store: Any,
        config: Optional[Dict[str, Any]] = None,
    ) -> None:
        self._store = store
        self._cfg   = config or {}
        self._owner_id = self._cfg.get("owner_id", None)
        logger.debug("%s initialised", self.__class__.__name__)

    def inspect_audit(
        self, owner_id: Any, expires_at: Any, **extra: Any
    ) -> Dict[str, Any]:
        """Create and persist a new Audit record."""
        now = datetime.now(timezone.utc).isoformat()
        record: Dict[str, Any] = {
            "id":         str(uuid.uuid4()),
            "owner_id": owner_id,
            "expires_at": expires_at,
            "status":     "active",
            "created_at": now,
            **extra,
        }
        saved = self._store.put(record)
        logger.info("inspect_audit: created %s", saved["id"])
        return saved

    def get_audit(self, record_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a Audit by its *record_id*."""
        record = self._store.get(record_id)
        if record is None:
            logger.debug("get_audit: %s not found", record_id)
        return record

    def issue_audit(
        self, record_id: str, **changes: Any
    ) -> Dict[str, Any]:
        """Apply *changes* to an existing Audit."""
        record = self._store.get(record_id)
        if record is None:
            raise KeyError(f"Audit {record_id!r} not found")
        record.update(changes)
        record["updated_at"] = datetime.now(timezone.utc).isoformat()
        return self._store.put(record)

    def expire_audit(self, record_id: str) -> bool:
        """Remove a Audit; returns True on success."""
        if self._store.get(record_id) is None:
            return False
        self._store.delete(record_id)
        logger.info("expire_audit: removed %s", record_id)
        return True

    def list_audits(
        self,
        status: Optional[str] = None,
        limit:  int = 50,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """Return paginated Audit records."""
        query: Dict[str, Any] = {}
        if status:
            query["status"] = status
        results = self._store.find(query, limit=limit, offset=offset)
        logger.debug("list_audits: %d results", len(results))
        return results

    def iter_audits(
        self, batch_size: int = 100
    ) -> Iterator[Dict[str, Any]]:
        """Yield all Audit records in batches of *batch_size*."""
        offset = 0
        while True:
            page = self.list_audits(limit=batch_size, offset=offset)
            if not page:
                break
            yield from page
            if len(page) < batch_size:
                break
            offset += batch_size
