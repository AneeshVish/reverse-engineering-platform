# reveng-desktop

**Status:** Ownership reservation (transitional)  
**Notes:** Desktop application entrypoint. Product code remains under repo-root `src/` until migration step 4 (Engineering Phase 001 §23).

Core runtime dependencies for launching `main.py` are declared in this package's `pyproject.toml` so `uv sync` installs them into the workspace venv.
