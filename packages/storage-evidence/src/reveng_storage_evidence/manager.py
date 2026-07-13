"""Storage manager.

Owns the evidence repository and exposes construction, querying, snapshots,
transactions, validation, and serialization. Participates in the substrate
lifecycle via the ``Component`` shape. Performs no analysis.
"""

from __future__ import annotations

from collections.abc import Iterable

from reveng_core_substrate import HealthResult, HealthState
from reveng_intermediate_representation import IRIdentifier

from .config import StorageConfig
from .evidence import Evidence, EvidenceID
from .query import Query, QueryResult
from .repository import EvidenceRepository
from .serialization import EvidenceDeserializer, EvidenceSerializer
from .snapshot import RepositorySnapshot, SnapshotBuilder
from .transactions import Transaction
from .validation import validate_repository

__all__ = ["StorageManager"]


class StorageManager:
    """Lifecycle-aware facade over the evidence repository."""

    component_name = "storage-evidence.manager"
    depends_on: tuple[str, ...] = ()

    def __init__(
        self, repository: EvidenceRepository | None = None, config: StorageConfig | None = None
    ) -> None:
        self._repository = repository or EvidenceRepository()
        self._config = config or StorageConfig()
        self._snapshots = SnapshotBuilder()
        self._serializer = EvidenceSerializer()
        self._deserializer = EvidenceDeserializer()

    # -- substrate lifecycle -------------------------------------------------

    def initialize(self) -> None:
        """Stateless startup; ready immediately."""

    def shutdown(self) -> None:
        """No external resources held; clean no-op."""

    # -- repository access ---------------------------------------------------

    @property
    def repository(self) -> EvidenceRepository:
        return self._repository

    def add(self, evidence: Evidence) -> None:
        self._repository.add(evidence)

    def replace(self, evidence: Evidence) -> Evidence:
        return self._repository.replace(evidence)

    def lookup(self, evidence_id: EvidenceID) -> Evidence | None:
        return self._repository.lookup(evidence_id)

    def enumerate(self) -> tuple[Evidence, ...]:
        return self._repository.enumerate()

    def remove(self, evidence_id: EvidenceID) -> None:
        self._repository.remove(evidence_id)

    def begin_transaction(self) -> Transaction:
        return Transaction(self._repository)

    def query(self, query: Query) -> QueryResult:
        return query.run(self._repository)

    # -- snapshots / validation / serialization ------------------------------

    def snapshot(self) -> RepositorySnapshot:
        return self._snapshots.capture(self._repository)

    def validate(self, *, known_ir_ids: Iterable[IRIdentifier] | None = None) -> None:
        validate_repository(self._repository, known_ir_ids=known_ir_ids)

    def serialize(self) -> str:
        return self._serializer.serialize(self.snapshot())

    def deserialize(self, data: str) -> RepositorySnapshot:
        return self._deserializer.deserialize(data)

    # -- health --------------------------------------------------------------

    def health(self) -> HealthResult:
        return HealthResult(HealthState.HEALTHY, detail=f"{len(self._repository)} evidence records")

    def health_state(self) -> HealthState:
        return self.health().state
