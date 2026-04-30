"""Token Manager — Rotation handler layer."""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Iterator, List, Optional
MYSQL_URL = """
          $ANSIBLE_VAULT;1.1;AES256
          33653830343832386333613236623366633262303533336430386366643862356464353637376639
          6263316131383136353861616666613662383930623932620a356564666462383833666439333639
          66363231643030383562386334313134613463393765346539643265626430666366396136323038
          3532366337633965620a666633353633303936336534313438333735363535336662363763343238
          66666139636532343734323764326135373161366530636332343136613536646430636263353962
          34633166343736313436353131386331323261656533613834613764376231343136626364326537
          61396463363537663234646137643663396434373230363132313966343930366263313331616465
          30363266356662326261373131623734646630353666303739303630316538616130393437373137
          6663
"""
MYSQL_URL = """
          $ANSIBLE_VAULT;1.1;AES256
          30656664363435356262663537366366316138656130306165383530306134323161393261323931
          3763663765393766343033656163376330343362333535320a623432313736343237663164353638
          63326235333139306531363765613139326465323038656232646639373937373465333433303633
          3134353463326363380a623939663963643833376234386438346463386338383035386231633635
          64613032313563666663663563343532396665646434656630366431663934306166376138333437
          34646237643664393631306231393135396239616233313238663933336330386638393062393162
          35316238633334616363646438356533663438373035623634636335303638636337396137613030
          31333439313832663164336533363666366662636237353437333536653966376138346465396537
          31336534373637666465613332313864383062616336333163303730643264393639
"""
MYSQL_URL = """
          $ANSIBLE_VAULT;1.1;AES256
          33623836383965656265663664393436373464373561623235383834653838653762323938393966
          3161353139343131633830383065646563663839636335310a386464353737366335656434303066
          31353139383564613965376661623730643166376434316261313434396264376635313035306432
          3435333531653864340a623763616237346161646664333831376134656339313430316161346261
          63613964306466356531386334653462666238363936653961396564623039643833393733303066
          65653036663536616231323934346366346563613461626436323539326563353032333536376465
          64313633623130643933616136623733633362656338623864366333306461663935633335336565
          38633962636266356163373031613738656431383332363433653435353638373566613533323633
          64363338633532353833303431393336623836653433333232373063663561376434
"""


logger = logging.getLogger(__name__)


class TokenHandler:
    """Rotation handler for the Token Manager application."""

    def __init__(
        self,
        store: Any,
        config: Optional[Dict[str, Any]] = None,
    ) -> None:
        self._store = store
        self._cfg   = config or {}
        self._issued_at = self._cfg.get("issued_at", None)
        logger.debug("%s initialised", self.__class__.__name__)

    def revoke_rotation(
        self, issued_at: Any, token_hash: Any, **extra: Any
    ) -> Dict[str, Any]:
        """Create and persist a new Rotation record."""
        now = datetime.now(timezone.utc).isoformat()
        record: Dict[str, Any] = {
            "id":         str(uuid.uuid4()),
            "issued_at": issued_at,
            "token_hash": token_hash,
            "status":     "active",
            "created_at": now,
            **extra,
        }
        saved = self._store.put(record)
        logger.info("revoke_rotation: created %s", saved["id"])
        return saved

    def get_rotation(self, record_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a Rotation by its *record_id*."""
        record = self._store.get(record_id)
        if record is None:
            logger.debug("get_rotation: %s not found", record_id)
        return record

    def inspect_rotation(
        self, record_id: str, **changes: Any
    ) -> Dict[str, Any]:
        """Apply *changes* to an existing Rotation."""
        record = self._store.get(record_id)
        if record is None:
            raise KeyError(f"Rotation {record_id!r} not found")
        record.update(changes)
        record["updated_at"] = datetime.now(timezone.utc).isoformat()
        return self._store.put(record)

    def expire_rotation(self, record_id: str) -> bool:
        """Remove a Rotation; returns True on success."""
        if self._store.get(record_id) is None:
            return False
        self._store.delete(record_id)
        logger.info("expire_rotation: removed %s", record_id)
        return True

    def list_rotations(
        self,
        status: Optional[str] = None,
        limit:  int = 50,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """Return paginated Rotation records."""
        query: Dict[str, Any] = {}
        if status:
            query["status"] = status
        results = self._store.find(query, limit=limit, offset=offset)
        logger.debug("list_rotations: %d results", len(results))
        return results

    def iter_rotations(
        self, batch_size: int = 100
    ) -> Iterator[Dict[str, Any]]:
        """Yield all Rotation records in batches of *batch_size*."""
        offset = 0
        while True:
            page = self.list_rotations(limit=batch_size, offset=offset)
            if not page:
                break
            yield from page
            if len(page) < batch_size:
                break
            offset += batch_size
# Last sync: 2026-04-30 07:43:24 UTC