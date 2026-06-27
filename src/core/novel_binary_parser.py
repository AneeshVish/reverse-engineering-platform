import struct
import math
import json
from collections import Counter
import os

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

class NovelBinaryParser:
    """
    Novel, explainable, and robust binary format detector and section extractor.
    - Uses deep signature matching, entropy/statistics, and explainable logic.
    - Recovers info from corrupted/obfuscated binaries.
    - Extensible with user-provided signatures from YAML or JSON.
    - Advanced section parsing for PE, ELF, and Mach-O.
    """
    SIGNATURES = []

    def __init__(self, user_signatures=None, signature_path=None):
        # Load signatures from YAML/JSON file if provided
        if signature_path and os.path.exists(signature_path):
            if YAML_AVAILABLE and signature_path.endswith(('.yaml', '.yml')):
                with open(signature_path, 'r') as f:
                    self.SIGNATURES = yaml.safe_load(f)
            elif signature_path.endswith('.json'):
                with open(signature_path, 'r') as f:
                    self.SIGNATURES = json.load(f)
        elif not self.SIGNATURES:
            # Default signatures
            self.SIGNATURES = [
                {"name": "PE", "offset": 0, "magic": b"MZ", "structural": ["e_lfanew"]},
                {"name": "ELF", "offset": 0, "magic": b"\x7fELF"},
                # Name must match the FileType.MACHO enum member (was "Mach-O", which
                # never mapped and made every Mach-O fall back to RAW). Includes 32-bit
                # thin magics and fat/universal magics (0xCAFEBABE / 0xBEBAFECA).
                {"name": "MACHO", "offset": 0, "magic": [
                    b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf",   # 64-bit thin (LE/BE)
                    b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xce",   # 32-bit thin (LE/BE)
                    b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",   # fat/universal
                ]},
            ]
        if user_signatures:
            self.SIGNATURES.extend(user_signatures)

    @staticmethod
    def entropy(data):
        if not data:
            return 0.0
        counter = Counter(data)
        total = len(data)
        return -sum(count/total * math.log2(count/total) for count in counter.values())

    def detect_format(self, data):
        results = []
        rationale = []
        for sig in self.SIGNATURES:
            magic = sig["magic"] if isinstance(sig["magic"], list) else [sig["magic"]]
            for m in magic:
                if data[sig["offset"]:sig["offset"]+len(m)] == m:
                    rationale.append(f"Matched magic bytes at offset {sig['offset']}: {m}")
                    results.append(sig["name"])
        # Disambiguate CAFEBABE: it is BOTH the fat Mach-O magic and the Java
        # .class magic. In a fat Mach-O the 4 bytes after the magic are nfat_arch
        # (the number of architectures: realistically 1..29). In a Java class they
        # are minor+major version (major >= 45), so the value is large.
        if "MACHO" in results and data[:4] == b"\xca\xfe\xba\xbe" and len(data) >= 8:
            nfat = struct.unpack_from(">I", data, 4)[0]
            if nfat >= 30:
                results = [r for r in results if r != "MACHO"]
                results.append("JAVA")
                rationale.append(f"CAFEBABE with version field {nfat} -> Java .class, not Mach-O")
        # Heuristic: check for PE e_lfanew pointer
        if len(data) > 0x3c+4 and data[:2] == b"MZ":
            e_lfanew = struct.unpack_from("<I", data, 0x3c)[0]
            if e_lfanew < len(data):
                if data[e_lfanew:e_lfanew+4] == b"PE\0\0":
                    rationale.append(f"Valid PE header at e_lfanew: {e_lfanew}")
                    results.append("PE")
        # Entropy-based anomaly detection
        ent = self.entropy(data[:4096])
        if ent > 7.5:
            rationale.append(f"High entropy: {ent:.2f} (may be packed or encrypted)")
        # Confidence
        format_counts = Counter(results)
        if format_counts:
            fmt, count = format_counts.most_common(1)[0]
            confidence = min(1.0, 0.7 + 0.1*count)
        else:
            fmt, confidence = "Unknown", 0.0
        return {
            "type": fmt,
            "confidence": confidence,
            "rationale": rationale,
            "entropy": ent,
        }

    def parse_sections(self, data, file_type):
        """
        Advanced section parsing for PE, ELF, and Mach-O binaries.
        Returns a list of section dicts with name, offset, and size.
        """
        sections = []
        try:
            if file_type == "PE" and len(data) > 0x3c+4:
                # Robust PE section parsing
                e_lfanew = struct.unpack_from("<I", data, 0x3c)[0]
                if data[e_lfanew:e_lfanew+4] == b"PE\0\0":
                    num_sections = struct.unpack_from("<H", data, e_lfanew+6)[0]
                    opt_header_size = struct.unpack_from("<H", data, e_lfanew+20)[0]
                    section_offset = e_lfanew + 24 + opt_header_size
                    for i in range(num_sections):
                        off = section_offset + i*40
                        name = data[off:off+8].rstrip(b"\x00").decode(errors="replace")
                        raw_ptr = struct.unpack_from("<I", data, off+20)[0]
                        raw_size = struct.unpack_from("<I", data, off+16)[0]
                        sections.append({"name": name, "offset": raw_ptr, "size": raw_size})
            elif file_type == "ELF" and data[:4] == b'\x7fELF':
                # ELF section header parsing
                # 32-bit or 64-bit?
                is_64 = data[4] == 2
                endian = '<' if data[5] == 1 else '>'
                if is_64:
                    e_shoff = struct.unpack_from(endian+'Q', data, 0x28)[0]
                    e_shentsize = struct.unpack_from(endian+'H', data, 0x3A)[0]
                    e_shnum = struct.unpack_from(endian+'H', data, 0x3C)[0]
                    e_shstrndx = struct.unpack_from(endian+'H', data, 0x3E)[0]
                else:
                    e_shoff = struct.unpack_from(endian+'I', data, 0x20)[0]
                    e_shentsize = struct.unpack_from(endian+'H', data, 0x2E)[0]
                    e_shnum = struct.unpack_from(endian+'H', data, 0x30)[0]
                    e_shstrndx = struct.unpack_from(endian+'H', data, 0x32)[0]
                # Section header string table
                shstrtab_off = e_shoff + e_shstrndx * e_shentsize
                if is_64:
                    shstrtab_ptr = struct.unpack_from(endian+'Q', data, shstrtab_off+0x18)[0]
                    shstrtab_size = struct.unpack_from(endian+'Q', data, shstrtab_off+0x20)[0]
                else:
                    shstrtab_ptr = struct.unpack_from(endian+'I', data, shstrtab_off+0x10)[0]
                    shstrtab_size = struct.unpack_from(endian+'I', data, shstrtab_off+0x14)[0]
                shstrtab = data[shstrtab_ptr:shstrtab_ptr+shstrtab_size]
                # Parse section headers
                for i in range(e_shnum):
                    off = e_shoff + i * e_shentsize
                    if is_64:
                        name_off = struct.unpack_from(endian+'I', data, off)[0]
                        sec_off = struct.unpack_from(endian+'Q', data, off+0x18)[0]
                        sec_size = struct.unpack_from(endian+'Q', data, off+0x20)[0]
                    else:
                        name_off = struct.unpack_from(endian+'I', data, off)[0]
                        sec_off = struct.unpack_from(endian+'I', data, off+0x10)[0]
                        sec_size = struct.unpack_from(endian+'I', data, off+0x14)[0]
                    # Get name from shstrtab
                    name = b''
                    if name_off < len(shstrtab):
                        for j in range(name_off, len(shstrtab)):
                            if shstrtab[j] == 0:
                                break
                            name += bytes([shstrtab[j]])
                    name_str = name.decode(errors="replace") if name else f"section_{i}"
                    sections.append({"name": name_str, "offset": sec_off, "size": sec_size})
            elif file_type == "Mach-O":
                # Minimal Mach-O section parsing (for 32/64-bit, little endian)
                # Only parse first segment/section table
                # Magic: 0xFEEDFACE (32-bit), 0xFEEDFACF (64-bit), or swapped
                magic = struct.unpack_from('>I', data, 0)[0]
                is_64 = magic in [0xFEEDFACF, 0xCFFAEDFE]
                endian = '>' if magic in [0xFEEDFACE, 0xFEEDFACF] else '<'
                ncmds = struct.unpack_from(endian+'I', data, 16)[0]
                off = 32 if is_64 else 28
                for _ in range(ncmds):
                    cmd = struct.unpack_from(endian+'I', data, off)[0]
                    cmdsize = struct.unpack_from(endian+'I', data, off+4)[0]
                    # LC_SEGMENT (0x1) or LC_SEGMENT_64 (0x19)
                    if (cmd == 0x1 and not is_64) or (cmd == 0x19 and is_64):
                        segname = data[off+8:off+24].rstrip(b'\x00').decode(errors="replace")
                        nsects = struct.unpack_from(endian+'I', data, off+40 if is_64 else off+36)[0]
                        sect_off = off + (72 if is_64 else 56)
                        for i in range(nsects):
                            secname = data[sect_off:sect_off+16].rstrip(b'\x00').decode(errors="replace")
                            addr = struct.unpack_from(endian+('Q' if is_64 else 'I'), data, sect_off+16)[0]
                            size = struct.unpack_from(endian+('Q' if is_64 else 'I'), data, sect_off+24)[0]
                            sections.append({"name": f"{segname}:{secname}", "offset": addr, "size": size})
                            sect_off += 80 if is_64 else 68
                    off += cmdsize
        except Exception as e:
            sections.append({"name": "error", "offset": 0, "size": 0, "rationale": f"Section parse failed: {e}"})
        return sections

    def recover_from_corruption(self, data):
        # Try to find magic bytes and reconstruct minimal info
        info = self.detect_format(data)
        # If PE, try to parse sections even if header is partial
        if info["type"] == "PE":
            try:
                info["sections"] = self.parse_sections(data, "PE")
            except Exception as e:
                info["sections"] = []
                info["rationale"].append(f"Section parse failed: {e}")
        return info

    def explain(self, data):
        info = self.detect_format(data)
        return json.dumps(info, indent=2)
