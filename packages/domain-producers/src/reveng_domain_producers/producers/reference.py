"""Reference producers.

Thin, deterministic producers covering the artifact categories the platform
recognizes. Each declares its magic/extensions, priority, and advertised
capabilities; none performs deep reverse engineering. They are the *initial*
implementations only — the registry is authoritative and open to third parties.

The raw-binary producer is the deliberate lowest-priority WEAK fallback so it wins
only when nothing more specific claims the source.
"""

from __future__ import annotations

from ..artifact import ArtifactType
from ..contracts import DEFAULT_PRIORITY, ClaimStrength, ProducerRequest
from .base import BaseProducer

__all__ = [
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
]

_ZIP_PREFIX = b"PK\x03\x04"


class PEProducer(BaseProducer):
    name = "pe"
    version = "1.0.0"
    artifact_type = ArtifactType.PE
    magic_prefixes = (b"MZ",)
    extensions = ("exe", "dll", "sys")
    capability_names = ("sections", "imports", "exports")
    min_size = 2


class ELFProducer(BaseProducer):
    name = "elf"
    version = "1.0.0"
    artifact_type = ArtifactType.ELF
    magic_prefixes = (b"\x7fELF",)
    extensions = ("so", "elf")
    capability_names = ("sections", "symbols", "segments")
    min_size = 4


class MachOProducer(BaseProducer):
    name = "macho"
    version = "1.0.0"
    artifact_type = ArtifactType.MACHO
    magic_prefixes = (
        b"\xfe\xed\xfa\xce",
        b"\xfe\xed\xfa\xcf",
        b"\xce\xfa\xed\xfe",
        b"\xcf\xfa\xed\xfe",
    )
    extensions = ("dylib",)
    capability_names = ("load_commands", "segments")
    min_size = 4


class DEXProducer(BaseProducer):
    name = "dex"
    version = "1.0.0"
    artifact_type = ArtifactType.DEX
    magic_prefixes = (b"dex\n",)
    extensions = ("dex",)
    capability_names = ("classes", "methods")
    min_size = 8


class _ZipProducer(BaseProducer):
    """Base for ZIP-container formats, disambiguated by extension."""

    magic_prefixes = (_ZIP_PREFIX,)
    min_size = 4
    #: Extension that upgrades a shared-magic ZIP claim to STRONG.
    strong_extension: str = ""

    def identify(self, request: ProducerRequest) -> ClaimStrength:
        if request.content.startswith(_ZIP_PREFIX):
            ext = (request.hint_extension or "").lstrip(".").lower()
            if ext == self.strong_extension:
                return ClaimStrength.STRONG
            return ClaimStrength.WEAK
        return ClaimStrength.NONE


class APKProducer(_ZipProducer):
    name = "apk"
    version = "1.0.0"
    artifact_type = ArtifactType.APK
    extensions = ("apk",)
    strong_extension = "apk"
    capability_names = ("manifest", "dex_entries", "resources")


class IPAProducer(_ZipProducer):
    name = "ipa"
    version = "1.0.0"
    artifact_type = ArtifactType.IPA
    extensions = ("ipa",)
    strong_extension = "ipa"
    capability_names = ("payload", "info_plist")


class JARProducer(_ZipProducer):
    name = "jar"
    version = "1.0.0"
    artifact_type = ArtifactType.JAR
    extensions = ("jar",)
    strong_extension = "jar"
    capability_names = ("manifest", "class_entries")


class DotNetProducer(BaseProducer):
    name = "dotnet"
    version = "1.0.0"
    artifact_type = ArtifactType.DOTNET
    # .NET assemblies are PE files; claim WEAK on PE magic and rely on the
    # extension hint, leaving STRONG PE claims to the PE producer by default.
    magic_prefixes = ()
    extensions = ("dll", "exe")
    capability_names = ("assembly_metadata", "il_streams")
    min_size = 2

    def identify(self, request: ProducerRequest) -> ClaimStrength:
        if request.content.startswith(b"MZ") and self._extension_matches(request):
            return ClaimStrength.WEAK
        return ClaimStrength.NONE

    def validate(self, request: ProducerRequest) -> bool:
        return request.content.startswith(b"MZ") and len(request.content) >= self.min_size


class FirmwareProducer(BaseProducer):
    name = "firmware"
    version = "1.0.0"
    artifact_type = ArtifactType.FIRMWARE
    extensions = ("firmware", "fw", "rom")
    capability_names = ("partitions", "bootloader")


class MemoryImageProducer(BaseProducer):
    name = "memory_image"
    version = "1.0.0"
    artifact_type = ArtifactType.MEMORY_IMAGE
    extensions = ("img", "dmp", "raw", "mem")
    capability_names = ("address_space",)


class SourceProjectProducer(BaseProducer):
    name = "source_project"
    version = "1.0.0"
    artifact_type = ArtifactType.SOURCE_PROJECT
    extensions = ("tar", "zip", "src")
    capability_names = ("file_tree",)


class RawBinaryProducer(BaseProducer):
    """Lowest-priority WEAK fallback that claims any non-empty content."""

    name = "raw_binary"
    version = "1.0.0"
    artifact_type = ArtifactType.RAW_BINARY
    capability_names = ("byte_stream",)
    priority = DEFAULT_PRIORITY - 50

    def identify(self, request: ProducerRequest) -> ClaimStrength:
        return ClaimStrength.WEAK if request.content else ClaimStrength.NONE

    def validate(self, request: ProducerRequest) -> bool:
        return bool(request.content)


REFERENCE_PRODUCER_TYPES: tuple[type[BaseProducer], ...] = (
    PEProducer,
    ELFProducer,
    MachOProducer,
    APKProducer,
    IPAProducer,
    DEXProducer,
    JARProducer,
    DotNetProducer,
    FirmwareProducer,
    MemoryImageProducer,
    SourceProjectProducer,
    RawBinaryProducer,
)
