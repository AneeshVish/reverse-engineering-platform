"""Domain-producer tests: artifact identification."""

from __future__ import annotations

import pytest
from reveng_domain_producers import ArtifactType, identify_type


@pytest.mark.parametrize(
    ("content", "ext", "expected"),
    [
        (b"MZ\x90\x00", None, ArtifactType.PE),
        (b"\x7fELF\x02", None, ArtifactType.ELF),
        (b"\xfe\xed\xfa\xcf", None, ArtifactType.MACHO),
        (b"dex\n035\x00", None, ArtifactType.DEX),
        (b"PK\x03\x04rest", "apk", ArtifactType.APK),
        (b"PK\x03\x04rest", "ipa", ArtifactType.IPA),
        (b"PK\x03\x04rest", "jar", ArtifactType.JAR),
        (b"PK\x03\x04rest", None, ArtifactType.JAR),  # zip default
        (b"\x00\x01\x02", "img", ArtifactType.MEMORY_IMAGE),
        (b"\x00\x01\x02", None, ArtifactType.RAW_BINARY),
        (b"", None, ArtifactType.UNKNOWN),
    ],
)
def test_identify(content: bytes, ext: str | None, expected: ArtifactType) -> None:
    assert identify_type(content, ext) is expected


def test_identify_is_pure() -> None:
    content = b"MZ\x90\x00"
    assert identify_type(content, "exe") is identify_type(content, "exe")
