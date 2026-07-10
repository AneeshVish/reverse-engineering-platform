"""Built-in reference producers and their registration helper.

``register_builtin_producers`` registers the *reference set only*. The
``ProducerRegistry`` remains authoritative and open — third-party producers are
registered through :class:`ProducerFactory` on equal footing.
"""

from __future__ import annotations

from ..factory import ProducerFactory
from ..registry import ProducerRegistry
from .base import BaseProducer
from .reference import (
    REFERENCE_PRODUCER_TYPES,
    APKProducer,
    DEXProducer,
    DotNetProducer,
    ELFProducer,
    FirmwareProducer,
    IPAProducer,
    JARProducer,
    MachOProducer,
    MemoryImageProducer,
    PEProducer,
    RawBinaryProducer,
    SourceProjectProducer,
)

__all__ = [
    "BaseProducer",
    "PEProducer",
    "ELFProducer",
    "MachOProducer",
    "APKProducer",
    "IPAProducer",
    "DEXProducer",
    "JARProducer",
    "DotNetProducer",
    "FirmwareProducer",
    "MemoryImageProducer",
    "RawBinaryProducer",
    "SourceProjectProducer",
    "REFERENCE_PRODUCER_TYPES",
    "register_builtin_producers",
]


def register_builtin_producers(registry: ProducerRegistry) -> None:
    """Register the reference producers into ``registry`` via the factory."""

    factory = ProducerFactory(registry)
    factory.register_all(tuple(cls() for cls in REFERENCE_PRODUCER_TYPES))
