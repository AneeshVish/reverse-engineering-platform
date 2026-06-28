import os
import subprocess
import logging

# Optional: import frida, qiling, angr if available
try:
    import frida
except ImportError:
    frida = None
try:
    import qiling
except ImportError:
    qiling = None
try:
    import angr
except ImportError:
    angr = None

class AdvancedUnpacker:
    def __init__(self):
        self.logger = logging.getLogger('src.core.advanced_unpacking')

    def detect_packer(self, file_path):
        """Detect packers using PEiD signatures (pure Python, no diec required)."""
        try:
            import pefile
            from src.core.peid_signatures import PEID_SIGNATURES
            pe = pefile.PE(file_path, fast_load=True)
            # Scan for signature matches
            sig_results = []
            for sig in PEID_SIGNATURES:
                if sig['ep_only']:
                    # Check only at entry point
                    ep_addr = pe.OPTIONAL_HEADER.AddressOfEntryPoint
                    ep_offset = pe.get_offset_from_rva(ep_addr)
                    data = pe.__data__[ep_offset:ep_offset+16]
                    if sig['sig'] in data:
                        sig_results.append(sig['name'])
                else:
                    # Check all sections
                    for section in pe.sections:
                        if sig['sig'] in section.Name or sig['sig'] in section.get_data()[:64]:
                            sig_results.append(sig['name'])
            if sig_results:
                return f"PEiD Signature(s) detected: {', '.join(set(sig_results))}"
            # If no signature, check entropy
            entropy = max([section.get_entropy() for section in pe.sections]) if pe.sections else 0
            if entropy > 7.2:
                return f"[Heuristic] High section entropy ({entropy:.2f}) - Possibly packed."
            return "No packer detected."
        except ImportError:
            return "pefile not installed. Run: pip install pefile"
        except Exception as e:
            if "DOS Header magic not found" in str(e):
                self.logger.info("PEiD detection: Not a PE file.")
                return "Not a PE file."
            else:
                self.logger.error(f"PEiD detection failed: {e}")
                return f"PEiD detection failed: {e}"

    def entropy_analysis(self, file_path):
        """Calculate entropy to detect packed/encrypted sections."""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            import math
            if not data:
                return 0.0
            occur = [0]*256
            for b in data:
                occur[b] += 1
            entropy = 0.0
            for c in occur:
                if c:
                    p = c/len(data)
                    entropy -= p * math.log2(p)
            return entropy
        except Exception as e:
            self.logger.error(f"Entropy analysis failed: {e}")
            return -1

    def static_patch_antidebug(self, file_path):
        """Patch known anti-debug instruction patterns (stub)."""
        # TODO: Implement using capstone/keystone
        self.logger.info(f"[STUB] Would patch anti-debug patterns in {file_path}")
        return False

    def run_frida_script(self, file_path, script_code):
        """Run a Frida script for dynamic anti-analysis bypass or dumping."""
        if not frida:
            self.logger.error("Frida not installed!")
            return None
        # This is a stub for research; real code would attach to a process and run script_code
        self.logger.info(f"[STUB] Would run Frida script on {file_path}")
        return None

    def qiling_emulate(self, file_path):
        """Emulate binary with Qiling and dump memory (stub)."""
        if not qiling:
            self.logger.error("Qiling not installed!")
            return None
        self.logger.info(f"[STUB] Would emulate and dump memory for {file_path}")
        return None

    def angr_symbolic_exec(self, file_path):
        """Try symbolic execution to recover logic from obfuscated/virtualized code (stub)."""
        if not angr:
            self.logger.error("angr not installed!")
            return None
        self.logger.info(f"[STUB] Would run symbolic execution for {file_path}")
        return None

    def brute_force_xor(self, data):
        """Try all single-byte XOR keys to brute-force decrypt simple encrypted blobs. For each candidate, attempt to detect format and decompile/disassemble if possible."""
        import binascii
        import io
        results = []
        for key in range(256):
            decrypted = bytes([b ^ key for b in data])
            detected = None
            code_snippet = None
            high_level = None
            try:
                # Detect PE
                if decrypted.startswith(b'MZ'):
                    detected = 'PE/EXE'
                    try:
                        import pefile
                        pe = pefile.PE(data=decrypted, fast_load=True)
                        code_snippet = f"Sections: {[s.Name.decode(errors='replace').strip() for s in pe.sections]}"
                        high_level = 'C/C++/ASM (native)'
                    except Exception:
                        code_snippet = 'Could not parse PE sections.'
                # Detect Python bytecode
                elif decrypted[:4] in [b'\x42\x0d\x0d\x0a', b'\x03\xf3\x0d\x0a', b'\x33\x0d\x0d\x0a'] or decrypted[:2] == b'\x03\xf3':
                    detected = 'Python Bytecode'
                    try:
                        import marshal
                        codeobj = marshal.loads(decrypted[16:])
                        code_snippet = repr(codeobj)
                        high_level = 'Python'
                    except Exception:
                        code_snippet = 'Could not parse Python bytecode.'
                # Detect Java class
                elif decrypted.startswith(b'\xca\xfe\xba\xbe'):
                    detected = 'Java .class'
                    code_snippet = 'Java bytecode detected.'
                    high_level = 'Java'
                # Detect WASM
                elif decrypted.startswith(b'\x00asm'):
                    detected = 'WebAssembly'
                    code_snippet = 'WASM binary detected.'
                    high_level = 'WebAssembly'
                # Detect ELF
                elif decrypted.startswith(b'\x7fELF'):
                    detected = 'ELF'
                    code_snippet = 'ELF binary detected.'
                    high_level = 'C/C++/ASM (native)'
                # Fallback: ASCII text
                elif all(32 <= b <= 126 or b in (9, 10, 13) for b in decrypted[:32]):
                    detected = 'ASCII text?'
                    code_snippet = decrypted[:128].decode(errors='replace')
                    high_level = 'Unknown/Text'
                # Otherwise, skip
                if detected:
                    results.append({
                        'key': key,
                        'format': detected,
                        'high_level': high_level,
                        'snippet': code_snippet
                    })
            except Exception:
                continue
        return results

    def dump_sections_after_runtime(self, file_path):
        """Run the binary, monitor for new code sections, and dump them (stub)."""
        self.logger.info(f"[STUB] Would run and dump runtime sections for {file_path}")
        return None

    # ----- REAL content recovery (honest: no "SHA-256 decryption") -----------

    def reveal_contents(self, file_path, max_bytes=8 * 1024 * 1024):
        """Reveal the ACTUAL recoverable data inside a file.

        This is the honest version of "show what's inside". It does NOT try to
        reverse one-way hashes (impossible). It DOES fully decode every open
        container we can: Apple binary/XML property lists, gzip/zlib/bz2/xz
        compression, zip archives, plus binary sections, printable strings, and
        base64/hex blobs that hide readable text. Returns a formatted report.
        """
        try:
            with open(file_path, "rb") as f:
                data = f.read(max_bytes)
        except OSError as e:
            return f"[ERROR] {e}"
        if not data:
            return "[EMPTY FILE] 0 bytes — nothing to reveal."

        out = [f"REVEALED CONTENTS — {os.path.basename(file_path)} ({len(data):,} bytes)"]
        magic = data[:16]
        revealed_structured = False

        # 1) Apple property list (binary 'bplist00' or XML) — the Info.plist case.
        stripped = data.lstrip()
        if magic[:6] == b"bplist" or stripped[:6] == b"<?xml " or stripped[:7] == b"<plist ":
            try:
                import plistlib
                obj = plistlib.loads(data)
                kind = "binary" if magic[:6] == b"bplist" else "XML"
                out.append(f"\n[PROPERTY LIST — {kind}, fully decoded]")
                out.extend(self._dump_structured(obj))
                revealed_structured = True
            except Exception as e:
                out.append(f"\n[PROPERTY LIST] could not parse: {e}")

        # 2) Compression containers — decompress and reveal the real payload.
        dec, algo = self._try_decompress(data)
        if dec is not None:
            out.append(f"\n[DECOMPRESSED — {algo}, {len(dec):,} bytes]")
            try:
                import plistlib
                if dec[:6] == b"bplist" or dec.lstrip()[:6] == b"<?xml ":
                    out.extend(self._dump_structured(plistlib.loads(dec)))
                    revealed_structured = True
                else:
                    raise ValueError
            except Exception:
                out.append(self._preview_text_or_strings(dec))
                revealed_structured = True

        # 3) Zip / jar / asar-as-zip — list real entries.
        import zipfile
        import io
        if zipfile.is_zipfile(io.BytesIO(data)):
            try:
                zf = zipfile.ZipFile(io.BytesIO(data))
                names = zf.namelist()
                out.append(f"\n[ZIP ARCHIVE — {len(names)} entries]")
                out.extend(f"  {n}" for n in names[:80])
                if len(names) > 80:
                    out.append(f"  … and {len(names) - 80} more")
                revealed_structured = True
            except Exception as e:
                out.append(f"\n[ZIP] {e}")

        # 4) Native binary — real sections (LIEF) + linked libraries.
        secs = self._binary_sections(file_path)
        if secs:
            out.append("\n[BINARY SECTIONS]")
            out.extend(secs)
            revealed_structured = True

        # 5) Always-useful for any blob: printable strings + decoded base64/hex.
        if not revealed_structured:
            out.append("\n[PRINTABLE STRINGS + DECODED BLOBS]")
            out.append(self._preview_text_or_strings(data))

        # 6) Honest footer about what is NOT recoverable.
        ent = self.entropy_analysis(file_path)
        out.append(f"\n[ENTROPY] {ent:.2f} / 8.0")
        if ent > 7.5 and not revealed_structured:
            out.append("Note: near-maximal entropy with no decodable structure means this is "
                        "genuinely compressed or encrypted. Without the key it cannot be "
                        "recovered — and one-way hashes (SHA-256, etc.) never can be, by anyone.")
        return "\n".join(out)

    @staticmethod
    def _try_decompress(data):
        """Return (decompressed_bytes, algo) for gzip/zlib/bz2/xz, else (None, '')."""
        import bz2
        import gzip
        import lzma
        import zlib
        import io
        if data[:2] == b"\x1f\x8b":
            try:
                return gzip.decompress(data), "gzip"
            except Exception:
                pass
        if data[:3] == b"BZh":
            try:
                return bz2.decompress(data), "bzip2"
            except Exception:
                pass
        if data[:6] == b"\xfd7zXZ\x00" or data[:5] == b"\x5d\x00\x00\x80\x00":
            try:
                return lzma.decompress(data), "xz/lzma"
            except Exception:
                pass
        if data[:1] in (b"\x78",):  # zlib stream
            try:
                return zlib.decompress(data), "zlib"
            except Exception:
                pass
        return None, ""

    @staticmethod
    def _dump_structured(obj, indent=2, depth=0, lines=None):
        """Recursively render a decoded dict/list (plist/json) as readable text."""
        if lines is None:
            lines = []
        pad = " " * indent
        if depth > 6:
            lines.append(f"{pad}…")
            return lines
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, (dict, list)):
                    lines.append(f"{pad}{k}:")
                    AdvancedUnpacker._dump_structured(v, indent + 2, depth + 1, lines)
                else:
                    lines.append(f"{pad}{k} = {v!r}"[:300])
        elif isinstance(obj, list):
            for i, v in enumerate(obj[:50]):
                if isinstance(v, (dict, list)):
                    lines.append(f"{pad}[{i}]:")
                    AdvancedUnpacker._dump_structured(v, indent + 2, depth + 1, lines)
                else:
                    lines.append(f"{pad}[{i}] = {v!r}"[:300])
        else:
            lines.append(f"{pad}{obj!r}"[:300])
        return lines

    @staticmethod
    def _preview_text_or_strings(data, limit=60):
        """If text, preview it; else extract printable strings + decode blobs."""
        head = data[:4096]
        printable = sum(32 <= c <= 126 or c in (9, 10, 13) for c in head)
        out = []
        if head and printable / len(head) > 0.85:
            out.append(data[:2000].decode("utf-8", "replace"))
        else:
            import re
            strings = re.findall(rb"[\x20-\x7e]{4,}", data)
            for s in strings[:limit]:
                out.append("  " + s.decode("latin-1"))
            if len(strings) > limit:
                out.append(f"  … {len(strings) - limit} more strings")
        try:
            from src.core.bundle_analysis import decode_blobs
            blobs = decode_blobs(data)
            if blobs:
                out.append("\n  Decoded base64/hex blobs (hidden text):")
                for kind, snippet, text in blobs[:10]:
                    out.append(f"    [{kind}] → {text}")
        except Exception:
            pass
        return "\n".join(out)

    @staticmethod
    def _binary_sections(file_path):
        """Real section table + libraries for a native binary via LIEF, else []."""
        try:
            import lief
            b = lief.parse(file_path)
            if b is None:
                return []
            lines = []
            for s in list(getattr(b, "sections", []) or [])[:40]:
                name = getattr(s, "name", "?")
                size = getattr(s, "size", 0)
                lines.append(f"  {name:<24} size={size:,}")
            libs = list(getattr(b, "libraries", []) or [])
            if libs:
                names = [getattr(lb, "name", str(lb)) if not isinstance(lb, str) else lb
                         for lb in libs[:25]]
                lines.append("  Linked libraries: " + ", ".join(names))
            return lines
        except Exception:
            return []

    # Add more methods as needed for advanced anti-analysis bypass

# Example usage (to be integrated with FullSoftwarePanel):
# unpacker = AdvancedUnpacker()
# packer_info = unpacker.detect_packer(file_path)
# entropy = unpacker.entropy_analysis(file_path)
# ...
