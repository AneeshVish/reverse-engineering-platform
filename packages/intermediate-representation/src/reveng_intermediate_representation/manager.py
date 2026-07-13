"""IR manager.

Owns the builder entry point, validator, and serializers, and participates in
the substrate lifecycle via the ``Component`` shape. It performs no analysis and
holds no IR state between calls.
"""

from __future__ import annotations

from reveng_core_substrate import HealthResult, HealthState

from .builders import IRBuilder, ModuleBuilder
from .config import IRConfig
from .nodes import IRModule
from .serialization import IRDeserializer, IRSerializer
from .validation import IRValidator

__all__ = ["IRManager"]


class IRManager:
    """Lifecycle-aware facade over IR construction, validation, serialization."""

    component_name = "intermediate-representation.manager"
    depends_on: tuple[str, ...] = ()

    def __init__(self, config: IRConfig | None = None) -> None:
        self._config = config or IRConfig()
        self._builder = IRBuilder()
        self._validator = IRValidator()
        self._serializer = IRSerializer()
        self._deserializer = IRDeserializer()

    # -- substrate lifecycle -------------------------------------------------

    def initialize(self) -> None:
        """Stateless; ready immediately."""

    def shutdown(self) -> None:
        """No resources held; clean no-op."""

    # -- construction / validation / serialization ---------------------------

    def module_builder(
        self, name: str, *, architecture: str = "unknown", file_format: str = "unknown"
    ) -> ModuleBuilder:
        return self._builder.module(name, architecture=architecture, file_format=file_format)

    def validate(self, module: IRModule) -> None:
        self._validator.validate(module)

    def serialize(self, module: IRModule) -> str:
        return self._serializer.serialize(module)

    def deserialize(self, data: str) -> IRModule:
        return self._deserializer.deserialize(data)

    # -- health --------------------------------------------------------------

    def health(self) -> HealthResult:
        return HealthResult(HealthState.HEALTHY, detail="ir manager ready")

    def health_state(self) -> HealthState:
        return self.health().state
