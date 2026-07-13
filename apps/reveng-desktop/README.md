# reveng-desktop

**Status:** Ownership reservation (transitional)  
**Notes:** Desktop application entrypoint. Product code remains under repo-root `src/` until migration step 4 (Engineering Phase 001 §23).

Core runtime dependencies for launching `main.py` are declared in this package's `pyproject.toml` so `uv sync` installs them into the workspace venv.

**Naming note (Engineering Phase 015):** the module `reveng_desktop` (this package) remains the reserved, still-unfilled entrypoint for the future modernized GUI. Engineering Phase 015's desktop integration/IPC client library lives in `packages/desktop-sdk` (module `reveng_desktop_sdk`) — a different importable name, chosen because `reveng_desktop` was already owned by this reservation.
