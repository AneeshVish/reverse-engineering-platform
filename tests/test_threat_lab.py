"""Tests for the Threat-Resistance Lab reporting/registry (no live simulation here).

The live suite (run_suite) is verified by running it manually on an owned host; CI
exercises only the pure logic — scoreboard formatting, registry integrity, and the
EICAR constant — so the test run never executes attacker-technique simulations.
"""

from src.core import threat_lab as tl


def test_eicar_constant_is_the_standard_string():
    assert tl.EICAR.startswith("X5O!P%@AP")
    assert tl.EICAR.endswith("EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
    assert len(tl.EICAR) == 68


def test_registry_is_well_formed():
    ids = [t[0] for t in tl.TECHNIQUES]
    assert len(ids) == len(set(ids)), "ATT&CK ids must be unique"
    for attack_id, name, tactic, severity, fn in tl.TECHNIQUES:
        assert attack_id.startswith("T")
        assert name and tactic
        assert severity in tl._SEV_RANK
        assert callable(fn)


def test_scoreboard_counts_and_verdict():
    results = [
        tl.TechniqueResult("T1486", "Ransomware", "Impact", "critical", "executed", "e"),
        tl.TechniqueResult("T1204", "EICAR", "Execution", "high", "blocked", "removed"),
        tl.TechniqueResult("T1573", "C2", "Command & Control", "high", "detected", "d"),
        tl.TechniqueResult("T1027", "Obfuscation", "Defense Evasion", "medium", "error", "x"),
    ]
    out = tl.format_scoreboard(results)
    assert "Deployed 4 benign technique simulations" in out
    assert "ALLOWED (got through): 1" in out
    assert "BLOCKED/DETECTED: 2" in out
    assert "ERRORS: 1" in out
    assert "allowed 1/4 attacker techniques" in out
    # critical sorts first
    assert out.index("T1486") < out.index("T1027")


def test_scoreboard_empty():
    assert "no techniques run" in tl.format_scoreboard([])
