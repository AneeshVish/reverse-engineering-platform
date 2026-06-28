"""Tests for the privilege-escalation attack-surface analyzer (static, no exploits)."""

import os
import stat

from src.core import privesc_surface as ps


def test_setuid_is_critical(tmp_path):
    p = tmp_path / "suid_bin"
    p.write_bytes(b"\x7fELF placeholder")
    os.chmod(p, 0o4755)  # setuid
    cats = {f.category: f.severity for f in ps.analyze(str(p))}
    # Some filesystems strip the setuid bit; only assert if it actually stuck.
    if os.stat(p).st_mode & stat.S_ISUID:
        assert cats.get("setuid binary") == "critical"


def test_world_writable_executable(tmp_path):
    p = tmp_path / "ww_bin"
    p.write_bytes(b"binary")
    os.chmod(p, 0o757)  # world-writable
    cats = {f.category for f in ps.analyze(str(p))}
    assert "world-writable executable" in cats


def test_clean_file_reports_no_surface(tmp_path):
    p = tmp_path / "clean.txt"
    p.write_text("hello")
    os.chmod(p, 0o644)
    findings = ps.analyze(str(p))
    assert findings == []
    assert "none detected" in ps.format_report(findings, str(p))


def test_report_sorted_by_severity():
    f = [ps.Finding("low", "a", "x"), ps.Finding("critical", "b", "y"),
         ps.Finding("medium", "c", "z")]
    f.sort(key=lambda x: ps._SEV_RANK[x.severity])
    assert [x.severity for x in f] == ["critical", "medium", "low"]
    out = ps.format_report(f, "t")
    assert "highest severity: CRITICAL" in out
