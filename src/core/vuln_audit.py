"""Concrete, location-aware vulnerability mapping.

Instead of regex-on-a-text-dump (which produced noise like "high entropy at offset
12"), this resolves every finding to exact coordinates and — the novel part —
cross-references where each weakness is actually USED in the code:

    file offset -> section -> virtual address -> enclosing function
                -> xrefs (the instructions/functions that reference it)

So a finding reads like: 'Hardcoded API key "AKIA..." in __cstring at 0x1f20,
referenced by sub_4012f0 at 0x4012a3' — concrete enough to jump straight to it.
"""

import bisect
import re
import struct
from dataclasses import dataclass, field
from typing import List


# ---- precise detectors (high precision; no substring guessing) -------------

# (label, severity, compiled-bytes-regex, value-group, needs_value_check)
# Precise formats capture the FULL secret; generic assignments require a quoted
# string value that passes _looks_like_secret() (kills code-identifier noise like
# `this.clientSecret` or variable names like `customPassword`).
SECRET_PATTERNS = [
    # Whole private-key block (header..footer), so the FULL key is shown.
    ("Private key", "critical",
     re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY-----"
                rb"[\s\S]{1,8192}?"
                rb"-----END (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY-----"), 0, False),
    ("AWS access key id", "critical", re.compile(rb"AKIA[0-9A-Z]{16}"), 0, False),
    ("AWS secret access key", "critical",
     re.compile(rb"(?i)aws.{0,20}?[\"']([A-Za-z0-9/+]{40})[\"']"), 1, True),
    ("Google API key", "high", re.compile(rb"AIza[0-9A-Za-z\-_]{35}"), 0, False),
    ("Slack token", "high", re.compile(rb"xox[baprs]-[0-9A-Za-z-]{10,48}"), 0, False),
    ("GitHub token", "high", re.compile(rb"gh[pousr]_[0-9A-Za-z]{20,}"), 0, False),
    ("Stripe secret key", "critical", re.compile(rb"sk_live_[0-9A-Za-z]{16,}"), 0, False),
    ("Private key (PEM body)", "critical",
     re.compile(rb"MII[A-Za-z0-9+/]{200,}={0,2}"), 0, False),
    ("JWT", "high",
     re.compile(rb"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{6,}"), 0, False),
    ("Hardcoded password", "high",
     re.compile(rb"(?i)(?:password|passwd|pwd)\s*[:=]\s*[\"']([^\"'\n]{6,80})[\"']"), 1, True),
    ("Hardcoded API key / secret", "high",
     re.compile(rb"(?i)(?:api[_-]?key|client[_-]?secret|secret[_-]?key|access[_-]?token|"
                rb"auth[_-]?token|private[_-]?key)\s*[:=]\s*[\"']([A-Za-z0-9\-_+=/]{8,200})[\"']"),
     1, True),
]

# Plain words / placeholders that are NOT real secret values.
_NOT_SECRETS = {
    "password", "passwd", "secret", "token", "changeme", "example", "test", "admin",
    "username", "user", "none", "null", "undefined", "true", "false", "yourpassword",
    "your_password", "your_api_key", "xxx", "todo", "placeholder", "string", "value",
    "default", "dummy", "sample", "redacted",
}


def _shannon(s):
    from collections import Counter
    import math
    if not s:
        return 0.0
    return -sum((c / len(s)) * math.log2(c / len(s)) for c in Counter(s).values())


def _looks_like_secret(v):
    """True if `v` looks like a real secret VALUE, not a code identifier/word."""
    if len(v) < 6:
        return False
    low = v.lower()
    if low in _NOT_SECRETS:
        return False
    # Code expression (property access / call / whitespace) -> not a literal secret.
    if any(ch in v for ch in ".()[] \t"):
        return False
    # A plain camelCase/identifier word with no digits is almost always a variable
    # name (clientSecret, customPassword), not a secret.
    if v.isalpha():
        return False
    # Require some randomness or length.
    return _shannon(v) >= 2.6 or len(v) >= 20

# Dangerous / weak imported functions (matched against the symbol table — exact,
# so no "des" inside "description" false positives). key -> (severity, why).
DANGEROUS_IMPORTS = {
    "gets": ("critical", "Unbounded read — classic stack buffer overflow."),
    "strcpy": ("high", "No bounds check — buffer overflow if source > dest."),
    "strcat": ("high", "No bounds check — buffer overflow."),
    "sprintf": ("high", "No bounds check — format/overflow risk."),
    "vsprintf": ("high", "No bounds check — overflow risk."),
    "scanf": ("medium", "Unbounded %s — overflow risk."),
    "system": ("high", "Shell execution — command injection if input is attacker-controlled."),
    "popen": ("high", "Shell execution — command injection risk."),
    "execve": ("medium", "Process execution — injection risk if args are tainted."),
    "tmpnam": ("medium", "Insecure temp file — race condition."),
    "mktemp": ("medium", "Insecure temp file — race condition."),
    "rand": ("low", "Non-cryptographic RNG — predictable if used for security."),
    # weak crypto primitives
    "MD5": ("medium", "Broken hash — not collision resistant."),
    "CC_MD5": ("medium", "Broken hash (CommonCrypto MD5)."),
    "SHA1": ("medium", "Weak hash — deprecated."),
    "CC_SHA1": ("medium", "Weak hash (CommonCrypto SHA1)."),
    "MD4": ("high", "Broken hash."),
    "DES": ("high", "Broken cipher — 56-bit key."),
    "RC4": ("high", "Broken stream cipher."),
}

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class Xref:
    addr: int          # instruction address that references the finding
    func: str          # function it lives in
    func_addr: int


@dataclass
class Finding:
    category: str
    severity: str
    value: str
    file_offset: int = -1
    section: str = ""
    vaddr: int = 0
    function: str = ""
    func_addr: int = 0
    xrefs: List[Xref] = field(default_factory=list)
    context: str = ""
    detail: str = ""

    def sort_key(self):
        return (_SEVERITY_ORDER.get(self.severity, 9), -len(self.xrefs), self.file_offset)


# ---- location + xref machinery ---------------------------------------------

_RIP_RE = re.compile(r"rip\s*([+\-])\s*(0x[0-9a-fA-F]+|\d+)")
_HEX_RE = re.compile(r"0x[0-9a-fA-F]+")
_ADRP_RE = re.compile(r"(\w+),\s*#?(0x[0-9a-fA-F]+)")
_ADD_RE = re.compile(r"(\w+),\s*(\w+),\s*#(0x[0-9a-fA-F]+|\d+)")
_LDR_RE = re.compile(r"\w+,\s*\[(\w+)(?:,\s*#(0x[0-9a-fA-F]+|\d+))?\]")


def _imm(s):
    return int(s, 16) if s and s.startswith("0x") else (int(s) if s else 0)


def _x86_refs(instr):
    """x86: RIP-relative or absolute address operands."""
    op = instr.get("op_str", "") or ""
    m = _RIP_RE.search(op)
    if m:
        disp = _imm(m.group(2))
        if m.group(1) == "-":
            disp = -disp
        return {instr.get("address", 0) + instr.get("size", 0) + disp}
    refs = set()
    for h in _HEX_RE.findall(op):
        try:
            refs.add(int(h, 16))
        except ValueError:
            pass
    return refs


class _FunctionIndex:
    """Nearest-preceding-function lookup by address."""

    def __init__(self, functions):
        fns = sorted(((int(f.get("address", 0)), f.get("name", "")) for f in functions),
                     key=lambda x: x[0])
        self._addrs = [a for a, _ in fns]
        self._names = [n for _, n in fns]

    def at(self, addr):
        if not self._addrs:
            return ("", 0)
        i = bisect.bisect_right(self._addrs, addr) - 1
        if i < 0:
            return ("", 0)
        a = self._addrs[i]
        name = self._names[i] or f"sub_{a:x}"
        return (name, a)


def _build_xref_index(instructions, fnindex):
    """Map referenced virtual address -> list of Xref (x86 RIP + ARM64 adrp/add/ldr)."""
    index = {}
    reg_page = {}   # ARM64 register -> page/base value from adrp/add chains

    def add_ref(target, ins):
        addr = ins.get("address", 0)
        fname, faddr = fnindex.at(addr)
        index.setdefault(target, []).append(Xref(addr, fname or f"sub_{faddr:x}", faddr))

    for ins in instructions:
        mn = (ins.get("mnemonic") or "").lower()
        op = ins.get("op_str", "") or ""
        if mn == "adrp":
            m = _ADRP_RE.search(op)
            if m:
                reg_page[m.group(1)] = _imm(m.group(2))
            continue
        if mn == "add":
            m = _ADD_RE.search(op)
            if m and m.group(2) in reg_page:
                target = reg_page[m.group(2)] + _imm(m.group(3))
                add_ref(target, ins)
                reg_page[m.group(1)] = target   # adrp+add forms the full address
                continue
        if mn.startswith("ldr") or mn.startswith("str"):
            m = _LDR_RE.search(op)
            if m and m.group(1) in reg_page:
                add_ref(reg_page[m.group(1)] + _imm(m.group(2)), ins)
                continue
        for target in _x86_refs(ins):
            add_ref(target, ins)
    return index


def _find_pointers_to(data, va):
    """File offsets where an 8-byte little-endian pointer to `va` is stored."""
    if not va:
        return []
    needle = struct.pack("<Q", va)
    out, start = [], 0
    while True:
        i = data.find(needle, start)
        if i < 0:
            break
        out.append(i)
        start = i + 1
        if len(out) > 16:
            break
    return out


def _section_for_offset(offset, sections):
    for s in sections:
        off = int(s.get("offset", 0))
        size = int(s.get("size", 0))
        if off <= offset < off + size:
            return s
    return None


def _sec_vaddr(s):
    return int(s.get("vaddr", s.get("virtual_address", 0)) or 0)


def _offset_to_vaddr(offset, sections):
    s = _section_for_offset(offset, sections)
    if s is None:
        return (0, "")
    va = _sec_vaddr(s) + (offset - int(s.get("offset", 0)))
    return (va, s.get("name", ""))


def _hexdump(data, offset, width=16, rows=4):
    out = []
    start = max(0, offset - width)
    for r in range(rows):
        base = start + r * width
        chunk = data[base:base + width]
        if not chunk:
            break
        hexs = " ".join(f"{b:02x}" for b in chunk)
        ascii_ = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        marker = "  <--" if base <= offset < base + width else ""
        out.append(f"  {base:08x}  {hexs:<47}  {ascii_}{marker}")
    return "\n".join(out)


# ---- main entry ------------------------------------------------------------

def audit(data, sections, functions, instructions, imports=None):
    """Run the concrete vulnerability map.

    sections: [{name, offset (file), vaddr, size}]
    functions: [{name, address}]
    instructions: [{address, size, mnemonic, op_str}]  (virtual addresses)
    imports: [str]  imported symbol names (optional)
    Returns a severity-sorted list[Finding].
    """
    sections = sections or []
    functions = functions or []
    instructions = instructions or []
    fnindex = _FunctionIndex(functions)
    xref_index = _build_xref_index(instructions, fnindex)
    findings = []

    # 1) Secrets / keys / tokens embedded in the binary, with xrefs to their use.
    seen = set()
    for label, severity, pat, grp, needs_check in SECRET_PATTERNS:
        for m in pat.finditer(data):
            has_grp = grp and m.lastindex and m.lastindex >= grp
            raw = m.group(grp) if has_grp else m.group(0)
            try:
                value = raw.decode("latin-1", "replace")
            except Exception:
                value = str(raw)
            if needs_check and not _looks_like_secret(value):
                continue
            offset = m.start(grp) if has_grp else m.start()
            key = value[:96]   # dedupe by value (precise patterns run first)
            if key in seen:
                continue
            seen.add(key)
            va, section = _offset_to_vaddr(offset, sections)
            is_code = "text" in (section or "").lower()
            fname, faddr = (fnindex.at(va) if (va and is_code) else ("", 0))
            # Direct xrefs to the value's address...
            xrefs = list(xref_index.get(va, [])) if va else []
            # ...plus indirect: code that loads a POINTER to it (common for
            # `const char *KEY = "..."`), so we still find the real usage site.
            if va:
                for ptr_off in _find_pointers_to(data, va):
                    pva, _ = _offset_to_vaddr(ptr_off, sections)
                    if pva:
                        xrefs.extend(xref_index.get(pva, []))
            # de-dup xrefs by instruction address
            _seen_x = set()
            xrefs = [x for x in xrefs if not (x.addr in _seen_x or _seen_x.add(x.addr))]
            findings.append(Finding(
                category=label, severity=severity, value=value[:8192],
                file_offset=offset, section=section or "(unmapped)", vaddr=va,
                function=fname, func_addr=faddr, xrefs=xrefs,
                context=_hexdump(data, offset),
                detail=(f"Embedded {label.lower()} at file offset {offset} "
                        f"({section or 'unmapped'}"
                        + (f", va 0x{va:x}" if va else "") + ").  "
                        + (f"Referenced by {len(xrefs)} code location(s) — jump to them "
                           "to see exactly where it is used."
                           if xrefs else "No direct code reference found in the disassembled range."))))

    # 2) Dangerous / weak imported functions (exact symbol matches).
    for name in (imports or []):
        base = name.lstrip("_")
        for token, (severity, why) in DANGEROUS_IMPORTS.items():
            if base == token or base.startswith(token + "_") or base.startswith("CC_" + token):
                findings.append(Finding(
                    category=f"Dangerous/weak import: {base}", severity=severity,
                    value=name, detail=f"{why}  The binary links {name}().",
                    context="Imported symbol (linked at the import/PLT table)."))
                break

    findings.sort(key=lambda f: f.sort_key())
    return findings


def audit_source_text(source_name, text_bytes):
    """Run the secret detectors over a text/source file (e.g. extracted Electron JS).

    Findings carry the file name + byte offset as their location (no VA/xref, since
    this is source, not a disassembled binary).
    """
    findings = []
    seen = set()
    for label, severity, pat, grp, needs_check in SECRET_PATTERNS:
        for m in pat.finditer(text_bytes):
            has_grp = grp and m.lastindex and m.lastindex >= grp
            raw = m.group(grp) if has_grp else m.group(0)
            try:
                value = raw.decode("latin-1", "replace")
            except Exception:
                value = str(raw)
            if needs_check and not _looks_like_secret(value):
                continue
            offset = m.start(grp) if has_grp else m.start()
            key = (source_name, value[:96])
            if key in seen:
                continue
            seen.add(key)
            findings.append(Finding(
                category=label, severity=severity, value=value[:8192],
                file_offset=offset, section=source_name, vaddr=0,
                detail=f"Embedded {label.lower()} in source file '{source_name}' at byte {offset}.\n\n"
                       f"Full value:\n{value[:8192]}"))
    return findings


def format_report(findings):
    if not findings:
        return "No concrete vulnerabilities mapped."
    from collections import Counter
    by_sev = Counter(f.severity for f in findings)
    lines = ["Concrete Vulnerability Map",
             "=" * 30,
             "  ".join(f"{s}: {by_sev.get(s, 0)}" for s in
                       ("critical", "high", "medium", "low")),
             ""]
    for f in findings:
        loc = f"{f.section} @ 0x{f.vaddr:x}" if f.vaddr else f.section or "import"
        lines.append(f"[{f.severity.upper()}] {f.category}")
        lines.append(f"    value:   {f.value}")
        lines.append(f"    where:   {loc}  (offset {f.file_offset})")
        if f.function:
            lines.append(f"    in func: {f.function} (0x{f.func_addr:x})")
        if f.xrefs:
            refs = ", ".join(f"{x.func}@0x{x.addr:x}" for x in f.xrefs[:8])
            lines.append(f"    used by: {refs}")
        lines.append("")
    return "\n".join(lines)
