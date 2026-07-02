"""Honest protection verdict: is this file encrypted, or just hashed/compressed/obfuscated?

A recurring reverse-engineering mistake is to see dense, random-looking bytes and
conclude "it's encrypted" — then try to "decrypt" it. Most of the time the truth
is far more mundable: it's compressed, it's a signature/certificate, it's minified
code, or it's just a normal binary. And a SHA-256 is a one-way hash that can NEVER
be reversed by anyone.

This module makes that call explicitly and defensibly, driven by evidence (magic
bytes, container structure, entropy, section layout) rather than vibes. Getting
this right is a credibility feature: it stops the tool (and the analyst) from
drawing wrong conclusions from static artifacts.
"""

import math
import os
import re
from dataclasses import dataclass


# Verdict labels (stable identifiers the UI can key on).
PLAINTEXT_CODE = "plaintext-code"
SCRIPT_SOURCE = "script-source"
MINIFIED = "minified-obfuscated"
COMPRESSED = "compressed"
ARCHIVE = "archive"
SIGNED = "signed-certificate"
IMAGE_MEDIA = "image-media"
PACKED = "packed"
ENCRYPTED_LIKELY = "encrypted-likely"
UNKNOWN = "unknown"


@dataclass
class Verdict:
    label: str
    headline: str          # one-line, human, demo-ready
    detail: str            # the evidence-based reasoning
    entropy: float
    recoverable: bool      # can its real contents be read without a secret key?

    def render(self) -> str:
        rec = ("Fully recoverable — no key needed." if self.recoverable
               else "Not recoverable without the key.")
        return (f"PROTECTION VERDICT: {self.headline}\n"
                f"  Evidence: {self.detail}\n"
                f"  Entropy:  {self.entropy:.2f} / 8.0\n"
                f"  {rec}")


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    ent = 0.0
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent


# Magic-byte containers that are dense but NOT encryption.
_COMPRESSION_MAGIC = {
    b"\x1f\x8b": "gzip",
    b"BZh": "bzip2",
    b"\xfd7zXZ\x00": "xz",
    b"\x28\xb5\x2f\xfd": "zstd",
    b"\x04\x22\x4d\x18": "lz4",
}
_ARCHIVE_MAGIC = {
    b"PK\x03\x04": "zip/jar/asar",
    b"PK\x05\x06": "zip (empty)",
    b"Rar!\x1a\x07": "rar",
    b"ustar": "tar",
    b"!<arch>": "ar/deb",
}
_IMAGE_MAGIC = {
    b"\x89PNG\r\n\x1a\n": "PNG",
    b"\xff\xd8\xff": "JPEG",
    b"GIF8": "GIF",
    b"RIFF": "RIFF (WebP/WAV/AVI)",
    b"\x00\x00\x01\x00": "ICO",
}
_NATIVE_MAGIC = {
    b"MZ": "PE/EXE",
    b"\x7fELF": "ELF",
    b"\xfe\xed\xfa\xce": "Mach-O (32)",
    b"\xfe\xed\xfa\xcf": "Mach-O (64)",
    b"\xcf\xfa\xed\xfe": "Mach-O (64, LE)",
    b"\xce\xfa\xed\xfe": "Mach-O (32, LE)",
    b"\xca\xfe\xba\xbe": "Mach-O (universal/fat)",
}

_SCRIPT_EXT = (".js", ".mjs", ".cjs", ".ts", ".py", ".rb", ".php", ".sh",
               ".pl", ".lua", ".json", ".html", ".css", ".xml", ".yaml", ".yml")
_SIGN_EXT = (".provisionprofile", ".mobileprovision", ".cer", ".der",
             ".p7b", ".p7s", ".pem", ".crt")


def _startswith_any(data: bytes, table):
    for magic, name in table.items():
        if data.startswith(magic):
            return name
    return None


def verdict_for_bytes(data: bytes, name: str = "") -> Verdict:
    """Classify a blob's protection state from its bytes + filename hint."""
    if not data:
        return Verdict(UNKNOWN, "Empty file", "0 bytes — nothing to assess.", 0.0, True)

    ent = shannon_entropy(data[: 1024 * 1024])
    lname = (name or "").lower()
    head = data[:64]

    # 1) Unambiguous containers first (magic beats entropy).
    comp = _startswith_any(head, _COMPRESSION_MAGIC)
    if comp:
        return Verdict(COMPRESSED, f"Compressed ({comp}) — NOT encrypted",
                       f"{comp} magic bytes; high entropy here is compression, not a cipher.",
                       ent, True)

    arch = _startswith_any(head, _ARCHIVE_MAGIC) or ("tar" if b"ustar" in data[:512] else None)
    if arch:
        return Verdict(ARCHIVE, f"Archive ({arch}) — NOT encrypted",
                       f"{arch} container; entries can be listed and extracted directly.",
                       ent, True)

    img = _startswith_any(head, _IMAGE_MAGIC)
    if img:
        return Verdict(IMAGE_MEDIA, f"Media/image ({img}) — NOT encrypted",
                       f"{img} magic; dense bytes are the encoded pixels/samples.",
                       ent, True)

    native = _startswith_any(head, _NATIVE_MAGIC)

    # 2) Signature / certificate artifacts (DER SEQUENCE or by extension/name).
    is_der = head[:1] == b"\x30" and head[1:2] in (b"\x81", b"\x82", b"\x83")
    if is_der or lname.endswith(_SIGN_EXT) or os.path.basename(lname) == "coderesources":
        return Verdict(SIGNED, "Code signature / certificate — NOT encrypted",
                       "Certificate chain + signature + file hashes; proves authenticity, "
                       "has no hidden plaintext to recover.", ent, True)

    # 3) Text / source / minified.
    sample = data[:4096]
    printable = sum(1 for b in sample if 32 <= b <= 126 or b in (9, 10, 13))
    text_ratio = printable / len(sample)
    if text_ratio > 0.90 or lname.endswith(_SCRIPT_EXT):
        # Minified/obfuscated if lines are enormous or whitespace is scarce.
        newline_ratio = sample.count(b"\n") / len(sample)
        if lname.endswith((".js", ".mjs", ".cjs")) and newline_ratio < 0.005:
            return Verdict(MINIFIED, "Minified/obfuscated source — readable, NOT encrypted",
                           "Valid script text with almost no line breaks (bundled/minified). "
                           "Beautifiable; all logic is present.", ent, True)
        return Verdict(SCRIPT_SOURCE, "Readable source / text — NOT encrypted",
                       f"{text_ratio*100:.0f}% printable; this is plaintext you can read directly.",
                       ent, True)

    # 4) Native binary — entropy tells packed vs. normal.
    if native:
        if ent > 7.2:
            return Verdict(PACKED, f"Packed {native} — compressed/obfuscated, not cipher-encrypted",
                           f"{native} with high entropy ({ent:.2f}); likely a packer (UPX/etc). "
                           "Unpack (often automatable) rather than 'decrypt'.", ent, True)
        return Verdict(PLAINTEXT_CODE, f"Plain {native} binary — NOT encrypted",
                       f"{native} with normal entropy ({ent:.2f}); disassembles directly. "
                       "Original source names/comments are gone (compilation is lossy), but "
                       "nothing is encrypted.", ent, True)

    # 5) No known structure. Now (and only now) entropy is the deciding signal.
    if ent > 7.5:
        return Verdict(ENCRYPTED_LIKELY, "Possibly encrypted — unrecognized, near-max entropy",
                       f"No known magic/container and entropy {ent:.2f}/8.0. Could be encryption, "
                       "a raw compressed stream, or a key/certificate blob. If truly encrypted, "
                       "it can only be read with the key — and no SHA-256 hash can be reversed.",
                       ent, False)
    return Verdict(UNKNOWN, "Unstructured data — no evidence of encryption",
                   f"No known container; moderate entropy ({ent:.2f}). Likely raw data or a "
                   "custom format, not encryption.", ent, True)


def verdict_for_file(file_path: str, max_bytes: int = 4 * 1024 * 1024) -> Verdict:
    try:
        with open(file_path, "rb") as f:
            data = f.read(max_bytes)
    except OSError as e:
        return Verdict(UNKNOWN, "Unreadable", f"{e}", 0.0, False)
    return verdict_for_bytes(data, os.path.basename(file_path))
