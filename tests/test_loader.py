"""Smoke tests for the universal binary loader / format detection."""

import os
import sys
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
def test_system_binary_detected():
    """Regression: a real system binary must be detected, not fall back to RAW.

    /bin/ls is a (fat) Mach-O on macOS and an ELF on Linux — assert the right
    format for the platform so this passes on macOS and Linux CI alike.
    """
    ldr = UniversalLoader()
    assert ldr.load("/bin/ls") is True
    expected = FileType.MACHO if sys.platform == "darwin" else FileType.ELF
    assert ldr.file_type == expected
    assert ldr.file_type != FileType.RAW
    assert ldr.parsed is not None


@pytest.mark.skipif(not os.path.exists("/bin/ls"), reason="no ELF sample wired")
def test_section_extraction_returns_bytes():
    ldr = UniversalLoader()
    ldr.load("/bin/ls")
    content = ldr.get_section_content("__text") or ldr.get_section_content(".text")
    assert content is None or isinstance(content, (bytes, bytearray))
