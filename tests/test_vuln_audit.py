"""Tests for the concrete vulnerability map (location + xref resolution)."""

from src.core import vuln_audit as va


def _sections():
    # __cstring data lives at file offset 0x100, virtual address 0x4000.
    return [{"name": "__cstring", "offset": 0x100, "virtual_address": 0x4000, "size": 0x100}]


def _data_with_secret():
    return b"\x00" * 0x100 + b"AKIAIOSFODNN7EXAMPLE" + b"\x00" * 0x40


def test_offset_to_vaddr():
    va_, sec = va._offset_to_vaddr(0x100, _sections())
    assert va_ == 0x4000 and sec == "__cstring"
    assert va._offset_to_vaddr(0x999, _sections()) == (0, "")


def test_arm64_adrp_add_xref():
    # adrp x0, 0x4000 ; add x0, x0, #0  -> references 0x4000
    ins = [
        {"address": 0x1000, "size": 4, "mnemonic": "adrp", "op_str": "x0, #0x4000"},
        {"address": 0x1004, "size": 4, "mnemonic": "add", "op_str": "x0, x0, #0"},
    ]
    funcs = [{"name": "check", "address": 0x1000}]
    findings = va.audit(_data_with_secret(), _sections(), funcs, ins, [])
    aws = [f for f in findings if "AWS" in f.category][0]
    assert aws.vaddr == 0x4000
    assert any(x.addr == 0x1004 and x.func == "check" for x in aws.xrefs)


def test_x86_rip_relative_xref():
    # lea rdi, [rip + disp] at 0x1000 (size 7) -> 0x1000+7+0x2ff9 = 0x4000
    ins = [{"address": 0x1000, "size": 7, "mnemonic": "lea", "op_str": "rdi, [rip + 0x2ff9]"}]
    funcs = [{"name": "main", "address": 0x1000}]
    findings = va.audit(_data_with_secret(), _sections(), funcs, ins, [])
    aws = [f for f in findings if "AWS" in f.category][0]
    assert any(x.addr == 0x1000 for x in aws.xrefs)


def test_secret_patterns():
    data = (b'password = "hunter2hunter2"\n'
            b"token eyJabcdefgh.eyJabcdefgh.sigsigsig\n"
            b"AIzaSyA1234567890abcdefghijklmnopqrstuvx\n")
    cats = {f.category for f in va.audit(data, [], [], [], [])}
    assert "Hardcoded password" in cats
    assert "JWT" in cats
    assert "Google API key" in cats


def test_dangerous_imports():
    findings = va.audit(b"nothing", [], [], [], ["_gets", "_strcpy", "_printf", "_MD5"])
    cats = {f.category: f.severity for f in findings}
    assert any("gets" in c for c in cats) and cats.get("Dangerous/weak import: gets") == "critical"
    assert any("strcpy" in c for c in cats)
    assert any("MD5" in c for c in cats)
    # printf is NOT dangerous -> not flagged
    assert not any("printf" in c for c in cats)


def test_no_substring_false_positive():
    # The old engine flagged 'des' inside 'description'. The new engine only flags
    # exact dangerous *imports*, so plain text yields nothing.
    findings = va.audit(b"this is a description of the design process", [], [], [], [])
    assert findings == []


def test_audit_source_text_finds_secrets_in_js():
    js = (b'const cfg = { api_key: "AKIAIOSFODNN7EXAMPLE", '
          b'password: "hunter2hunter2" };')
    findings = va.audit_source_text("bundle.js", js)
    cats = {f.category: f for f in findings}
    assert "AWS access key id" in cats
    assert cats["AWS access key id"].section == "bundle.js"
    assert any(f.category == "Hardcoded password" for f in findings)


def test_format_report_empty():
    assert "No concrete vulnerabilities" in va.format_report([])
