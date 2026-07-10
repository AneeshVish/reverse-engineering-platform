"""Thin artifact identification.

Sniffs a candidate :class:`ArtifactType` from leading magic bytes and an optional
extension hint. This is intentionally shallow — prefix bytes and extension only,
no deep parsing and no filesystem access — so it stays pure and deterministic.
Final producer choice is made by capability negotiation in ``selection.py``; this
is only a hint.
"""

from __future__ import annotations

from .artifact import ArtifactType

__all__ = ["identify_type", "MAGIC_PREFIXES"]

# Ordered longest-prefix-first where prefixes could overlap.
MAGIC_PREFIXES: tuple[tuple[bytes, ArtifactType], ...] = (
    (b"\x7fELF", ArtifactType.ELF),
    (b"dex\n", ArtifactType.DEX),
    (b"\xca\xfe\xba\xbe", ArtifactType.MACHO),  # Mach-O fat / Java class share this
    (b"\xfe\xed\xfa\xce", ArtifactType.MACHO),
    (b"\xfe\xed\xfa\xcf", ArtifactType.MACHO),
    (b"\xce\xfa\xed\xfe", ArtifactType.MACHO),
    (b"\xcf\xfa\xed\xfe", ArtifactType.MACHO),
    (b"MZ", ArtifactType.PE),
)

_EXTENSION_TYPES: dict[str, ArtifactType] = {
    "exe": ArtifactType.PE,
    "dll": ArtifactType.PE,
    "sys": ArtifactType.PE,
    "so": ArtifactType.ELF,
    "elf": ArtifactType.ELF,
    "dylib": ArtifactType.MACHO,
    "apk": ArtifactType.APK,
    "ipa": ArtifactType.IPA,
    "dex": ArtifactType.DEX,
    "jar": ArtifactType.JAR,
    "firmware": ArtifactType.FIRMWARE,
    "bin": ArtifactType.RAW_BINARY,
    "img": ArtifactType.MEMORY_IMAGE,
    "dmp": ArtifactType.MEMORY_IMAGE,
    "raw": ArtifactType.MEMORY_IMAGE,
}

_ZIP_PREFIX = b"PK\x03\x04"


def identify_type(content: bytes, hint_extension: str | None = None) -> ArtifactType:
    """Return the best-guess :class:`ArtifactType` for ``content``.

    Magic-byte matches win; ZIP-container types (APK/IPA/JAR) are disambiguated by
    the extension hint since they share the same magic. Falls back to the
    extension, then to ``RAW_BINARY`` for non-empty content, else ``UNKNOWN``.
    """

    ext = (hint_extension or "").lstrip(".").lower()

    if content.startswith(_ZIP_PREFIX):
        zip_type = _EXTENSION_TYPES.get(ext)
        if zip_type is not None and zip_type in (
            ArtifactType.APK,
            ArtifactType.IPA,
            ArtifactType.JAR,
        ):
            return zip_type
        return ArtifactType.JAR

    for prefix, artifact_type in MAGIC_PREFIXES:
        if content.startswith(prefix):
            return artifact_type

    if ext in _EXTENSION_TYPES:
        return _EXTENSION_TYPES[ext]

    if content:
        return ArtifactType.RAW_BINARY
    return ArtifactType.UNKNOWN
