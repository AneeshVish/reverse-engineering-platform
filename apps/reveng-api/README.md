# reveng-api

**Impl Spec:** 010
**Status:** Implemented (Engineering Phase 014)
**Layer:** Process entrypoint; ASGI app for the public API service.

Thin wrapper only — imports `create_app()` from `reveng_public_api` and
exposes it as `app` for `uvicorn reveng_api:app`, or run directly via
`python -m reveng_api`. No business logic lives here; everything is in
`reveng_public_api`.
