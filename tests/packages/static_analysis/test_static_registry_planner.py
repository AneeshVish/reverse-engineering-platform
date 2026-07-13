"""Static-analysis tests: registry and planner."""

from __future__ import annotations

import pytest
from _static_helpers import make_request
from reveng_domain_producers import ArtifactType
from reveng_static_analysis import (
    AnalysisPlanner,
    AnalyzerCapability,
    AnalyzerMetadata,
    AnalyzerRegistry,
    RegistrationError,
    register_builtin_analyzers,
)
from reveng_static_analysis.reference import ReferenceAnalyzer


class _PEOnly(ReferenceAnalyzer):
    identifier_ = "pe_only"
    capabilities_ = (AnalyzerCapability.HEADERS,)

    @property
    def metadata(self) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            identifier=self.identifier_,
            capabilities=self.capabilities_,
            applicable_types=(ArtifactType.PE,),
        )


def _registry() -> AnalyzerRegistry:
    reg = AnalyzerRegistry()
    register_builtin_analyzers(reg)
    return reg


def test_register_all_reference_analyzers() -> None:
    reg = _registry()
    assert len(reg) == 11
    assert "binary_header" in reg.identifiers()
    assert "strings" in reg.identifiers()


def test_duplicate_registration_rejected() -> None:
    reg = _registry()
    with pytest.raises(RegistrationError):
        register_builtin_analyzers(reg)  # already populated → duplicate


def test_missing_lookup_rejected() -> None:
    reg = AnalyzerRegistry()
    with pytest.raises(RegistrationError):
        reg.get("nope")


def test_plan_selects_all_applicable() -> None:
    reg = _registry()
    plan = AnalysisPlanner().plan(reg, make_request())
    assert len(plan) == 11


def test_plan_filters_by_artifact_type() -> None:
    reg = AnalyzerRegistry()
    reg.register(_PEOnly())
    # ELF artifact → the PE-only analyzer is not selected.
    plan = AnalysisPlanner().plan(reg, make_request(artifact_type=ArtifactType.ELF))
    assert plan.ordered_ids == ()
    plan_pe = AnalysisPlanner().plan(reg, make_request(artifact_type=ArtifactType.PE))
    assert plan_pe.ordered_ids == ("pe_only",)


def test_plan_is_deterministic() -> None:
    reg = _registry()
    req = make_request()
    plans = {AnalysisPlanner().plan(reg, req).ordered_ids for _ in range(5)}
    assert len(plans) == 1


def test_priority_orders_before_registration() -> None:
    class Hi(ReferenceAnalyzer):
        identifier_ = "hi"
        priority_ = 1000

    class Lo(ReferenceAnalyzer):
        identifier_ = "lo"

    reg = AnalyzerRegistry()
    reg.register(Lo())
    reg.register(Hi())
    plan = AnalysisPlanner().plan(reg, make_request())
    assert plan.ordered_ids == ("hi", "lo")
