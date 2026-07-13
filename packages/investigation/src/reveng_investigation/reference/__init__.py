"""Built-in reference investigations.

Eight deterministic investigations that group existing inferences into findings.
They perform no new reasoning, malware logic, or AI — each simply selects the
inferences produced by specific reasoning rules and organizes them.
"""

from __future__ import annotations

from reveng_reasoning import ReasoningResult

from ..finding import Finding, FindingKind, FindingSeverity
from .base import ReferenceInvestigation

__all__ = [
    "ReferenceInvestigation",
    "DeadCodeInvestigation",
    "UnusedFunctionInvestigation",
    "DuplicateSymbolInvestigation",
    "MissingEntryInvestigation",
    "UnresolvedImportInvestigation",
    "DuplicateEvidenceInvestigation",
    "NamespaceIntegrityInvestigation",
    "ReferenceIntegrityInvestigation",
    "REFERENCE_INVESTIGATION_TYPES",
    "run_reference_investigations",
]


class DeadCodeInvestigation(ReferenceInvestigation):
    kind_ = FindingKind.DEAD_CODE
    severity_ = FindingSeverity.LOW
    rule_ids_ = frozenset({"dead_section"})

    def name(self) -> str:
        return "Dead Code Investigation"


class UnusedFunctionInvestigation(ReferenceInvestigation):
    kind_ = FindingKind.UNUSED_FUNCTION
    severity_ = FindingSeverity.LOW
    rule_ids_ = frozenset({"unused_function"})

    def name(self) -> str:
        return "Unused Function Investigation"


class DuplicateSymbolInvestigation(ReferenceInvestigation):
    kind_ = FindingKind.DUPLICATE_SYMBOL
    severity_ = FindingSeverity.MEDIUM
    rule_ids_ = frozenset({"duplicate_symbol", "multiple_definitions"})

    def name(self) -> str:
        return "Duplicate Symbol Investigation"


class MissingEntryInvestigation(ReferenceInvestigation):
    kind_ = FindingKind.MISSING_ENTRY
    severity_ = FindingSeverity.HIGH
    rule_ids_ = frozenset({"missing_entry_symbol"})

    def name(self) -> str:
        return "Missing Entry Investigation"


class UnresolvedImportInvestigation(ReferenceInvestigation):
    kind_ = FindingKind.UNRESOLVED_IMPORT
    severity_ = FindingSeverity.HIGH
    rule_ids_ = frozenset({"unresolved_import"})

    def name(self) -> str:
        return "Unresolved Import Investigation"


class DuplicateEvidenceInvestigation(ReferenceInvestigation):
    kind_ = FindingKind.DUPLICATE_EVIDENCE
    severity_ = FindingSeverity.MEDIUM
    rule_ids_ = frozenset({"duplicate_evidence"})

    def name(self) -> str:
        return "Duplicate Evidence Investigation"


class NamespaceIntegrityInvestigation(ReferenceInvestigation):
    kind_ = FindingKind.NAMESPACE_INTEGRITY
    severity_ = FindingSeverity.LOW
    rule_ids_ = frozenset({"orphan_namespace"})

    def name(self) -> str:
        return "Namespace Integrity Investigation"


class ReferenceIntegrityInvestigation(ReferenceInvestigation):
    kind_ = FindingKind.REFERENCE_INTEGRITY
    severity_ = FindingSeverity.MEDIUM
    rule_ids_ = frozenset({"dangling_reference", "imported_but_not_referenced"})

    def name(self) -> str:
        return "Reference Integrity Investigation"


REFERENCE_INVESTIGATION_TYPES: tuple[type[ReferenceInvestigation], ...] = (
    DeadCodeInvestigation,
    UnusedFunctionInvestigation,
    DuplicateSymbolInvestigation,
    MissingEntryInvestigation,
    UnresolvedImportInvestigation,
    DuplicateEvidenceInvestigation,
    NamespaceIntegrityInvestigation,
    ReferenceIntegrityInvestigation,
)


def run_reference_investigations(reasoning: ReasoningResult) -> tuple[Finding, ...]:
    """Run every reference investigation and return all findings (unsorted)."""

    findings: list[Finding] = []
    for cls in REFERENCE_INVESTIGATION_TYPES:
        findings.extend(cls().build(reasoning))
    return tuple(findings)
