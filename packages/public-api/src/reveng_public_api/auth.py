"""Authentication hook -- framework only, no real credential checking.

Defines the seam a later phase can fill with real authentication/authorization
without touching any route signature. The default implementation is
deliberately permissive: it never rejects a request.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from fastapi import Header, HTTPException, Request

__all__ = ["AuthPrincipal", "AuthHook", "AllowAllAuthHook", "require_principal"]


@dataclass(frozen=True)
class AuthPrincipal:
    identifier: str


_ANONYMOUS_PRINCIPAL = AuthPrincipal(identifier="anonymous")


@runtime_checkable
class AuthHook(Protocol):
    """Resolves a bearer token (or ``None``) into a principal, or denies it."""

    def authenticate(self, token: str | None) -> AuthPrincipal | None: ...


class AllowAllAuthHook:
    """Permissive default: every request, authenticated or not, is allowed."""

    def authenticate(self, token: str | None) -> AuthPrincipal | None:
        return _ANONYMOUS_PRINCIPAL


def _bearer_token(authorization: str | None) -> str | None:
    if authorization is None:
        return None
    prefix = "Bearer "
    return authorization[len(prefix) :] if authorization.startswith(prefix) else authorization


def require_principal(
    request: Request, authorization: str | None = Header(default=None)
) -> AuthPrincipal:
    """FastAPI dependency resolving the wired ``AuthHook`` into a principal.

    Present as a seam on every protected router; the default hook never
    rejects, so this is a no-op in practice until a later phase supplies real
    authentication.
    """

    hook: AuthHook = request.app.state.service.auth_hook
    principal = hook.authenticate(_bearer_token(authorization))
    if principal is None:
        raise HTTPException(status_code=401, detail="unauthenticated")
    return principal
