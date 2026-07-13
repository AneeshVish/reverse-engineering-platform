"""The FastAPI application factory.

Pure wiring: builds the service via ``build_service``, stores it on
``app.state.service``, and includes the four routers. No business logic --
orchestration and its HTTP exposure are the only concerns here.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from .config import PublicApiConfig
from .init import ServiceContext, build_service
from .routers import health, jobs, plugins, upload

__all__ = ["create_app"]


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    yield
    service: ServiceContext = app.state.service
    service.application.shutdown()


def create_app(
    config: PublicApiConfig | None = None, *, service: ServiceContext | None = None
) -> FastAPI:
    """Construct the ASGI application, fully wired and ready to serve.

    ``service`` allows tests to inject a pre-built ``ServiceContext`` (e.g.
    with a ``FixedClock``/``MonotonicIdProvider`` or fault-injecting manager
    doubles) instead of the production composition built by ``build_service``.
    """

    service = service or build_service(config)

    app = FastAPI(title="RevENG Public API", version="0.1.0", lifespan=_lifespan)
    app.state.service = service

    app.include_router(upload.router)
    app.include_router(jobs.router)
    app.include_router(plugins.router)
    app.include_router(health.router)

    return app
