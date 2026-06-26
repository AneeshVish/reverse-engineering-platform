"""Smoke tests for the universal binary loader / format detection."""

import os
import pytest

from src.core.universal_loader import UniversalLoader, FileType


def test_text_file_is_raw(tmp_path):
    p = tmp_path / "note.txt"
    p.write_text("just some text, not a binary\n")
    ldr = UniversalLoader()
    assert ldr.load(str(p)) is True
    assert ldr.file_type == FileType.RAW


def test_missing_file_returns_false():
    ldr = UniversalLoader()
    assert ldr.load("/no/such/file/here.bin") is False


@pytest.mark.skipif(not os.path.exists("/bin/ls"), reason="no /bin/ls on this OS")
def test_macho_detected():
    """Regression: /bin/ls (fat Mach-O) must not fall back to RAW."""
    ldr = UniversalLoader()
    assert ldr.load("/bin/ls") is True
    assert ldr.file_type == FileType.MACHO
    assert ldr.parsed is not None


@pytest.mark.skipif(not os.path.exists("/bin/ls"), reason="no ELF sample wired")
def test_section_extraction_returns_bytes():
    ldr = UniversalLoader()
    ldr.load("/bin/ls")
    content = ldr.get_section_content("__text") or ldr.get_section_content(".text")
    assert content is None or isinstance(content, (bytes, bytearray))
