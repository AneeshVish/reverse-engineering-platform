"""reveng-api — the public API service entrypoint.

Thin process wrapper only; all logic lives in ``reveng_public_api``. Exposes
``app`` for ``uvicorn reveng_api:app``, or run directly via
``python -m reveng_api``.
"""

from __future__ import annotations

from reveng_public_api import create_app

__version__ = "0.1.0"

app = create_app()

__all__ = ["app", "__version__"]
