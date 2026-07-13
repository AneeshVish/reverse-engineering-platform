"""Construction helper for the public API service.

Wires the nine backend managers plus the plugin manager into one
``reveng_core_substrate.Application`` (so their existing lifecycle contracts
handle initialization/shutdown uniformly), builds the pipeline orchestrator
and job manager on top of them, and returns a single ``ServiceContext`` shared
by both ``app.py`` (the FastAPI factory) and the test suite.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import cast

from reveng_core_substrate import Application, HealthAggregator, HealthCheck, HealthResult
from reveng_domain_producers import ProducerManager, ProducerRegistry
from reveng_investigation import build_investigation_manager
from reveng_knowledge_graph import build_knowledge_graph
from reveng_plugin_sdk import PluginManager, build_plugin_manager
from reveng_reasoning import build_reasoning_engine
from reveng_reporting import build_reporting_manager
from reveng_static_analysis import build_static_analysis
from reveng_storage_evidence import build_storage_manager

from .auth import AllowAllAuthHook, AuthHook
from .config import PublicApiConfig, load_public_api_config
from .contracts import ClockProtocol, IdProvider
from .job_manager import JobManager
from .orchestrator import PipelineOrchestrator

__all__ = ["ServiceContext", "build_service"]


@dataclass
class ServiceContext:
    """The fully constructed, initialized service: one composition root."""

    application: Application
    orchestrator: PipelineOrchestrator
    job_manager: JobManager
    plugin_manager: PluginManager
    auth_hook: AuthHook
    config: PublicApiConfig

    def health(self) -> HealthResult:
        """Aggregate every wired component's health, mirroring PluginManager.health()."""

        aggregator = HealthAggregator()
        for name, component in self.application.components.items():
            health_check = getattr(component, "health", None)
            if callable(health_check):
                aggregator.register(name, cast(HealthCheck, health_check))
        overall = aggregator.evaluate().overall
        return HealthResult(overall, detail=f"{len(self.application.components)} components")


def build_service(
    config: PublicApiConfig | None = None,
    *,
    id_provider: IdProvider | None = None,
    clock: ClockProtocol | None = None,
    auth_hook: AuthHook | None = None,
) -> ServiceContext:
    """Construct and initialize the full service in one composition root."""

    resolved_config = config or load_public_api_config()

    producers = ProducerManager(ProducerRegistry())
    static_analysis = build_static_analysis()
    storage = build_storage_manager()
    knowledge_graph = build_knowledge_graph()
    reasoning = build_reasoning_engine()
    investigation = build_investigation_manager()
    reporting = build_reporting_manager()
    plugin_manager = build_plugin_manager()

    orchestrator = PipelineOrchestrator(
        producers=producers,
        static_analysis=static_analysis,
        storage=storage,
        knowledge_graph=knowledge_graph,
        reasoning=reasoning,
        investigation=investigation,
        reporting=reporting,
    )
    job_manager = JobManager(
        orchestrator,
        max_workers=int(resolved_config.get("job_pool_size")),
        id_provider=id_provider,
        clock=clock,
    )

    application = Application()
    for component in (
        producers,
        static_analysis,
        storage,
        knowledge_graph,
        reasoning,
        investigation,
        reporting,
        plugin_manager,
        job_manager,
    ):
        application.register_component(component)
    application.initialize()

    return ServiceContext(
        application=application,
        orchestrator=orchestrator,
        job_manager=job_manager,
        plugin_manager=plugin_manager,
        auth_hook=auth_hook or AllowAllAuthHook(),
        config=resolved_config,
    )
