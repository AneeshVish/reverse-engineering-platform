"""IR tests: deterministic identity."""

from __future__ import annotations

import pytest
from reveng_intermediate_representation import (
    IdentityError,
    IRNamespace,
    IRPath,
    derive_identifier,
)


def test_identifier_is_deterministic() -> None:
    path = IRPath.root().child("m").child("f")
    a = derive_identifier("function", path, "sig")
    b = derive_identifier("function", path, "sig")
    assert a == b
    assert a.value == b.value


def test_identifier_changes_with_kind_path_or_content() -> None:
    path = IRPath.root().child("m")
    base = derive_identifier("function", path, "c")
    assert derive_identifier("method", path, "c") != base
    assert derive_identifier("function", path.child("x"), "c") != base
    assert derive_identifier("function", path, "d") != base


def test_identifier_is_sha256_hex() -> None:
    ident = derive_identifier("module", IRPath.root().child("m"))
    assert len(ident.value) == 64
    assert all(c in "0123456789abcdef" for c in ident.value)


def test_empty_kind_raises_identity_error() -> None:
    with pytest.raises(IdentityError):
        derive_identifier("", IRPath.root())


def test_path_hierarchy() -> None:
    p = IRPath.root().child("a").child("b")
    assert p.segments == ("a", "b")
    assert p.canonical == "a/b"


def test_namespace_hierarchy() -> None:
    ns = IRNamespace.of("a").child("b")
    assert ns.qualified == "a.b"
    assert str(ns) == "a.b"


def test_no_wallclock_or_random_influence() -> None:
    # Deriving repeatedly across time yields identical identifiers.
    import time

    path = IRPath.root().child("m")
    first = derive_identifier("data", path, "x")
    time.sleep(0.01)
    assert derive_identifier("data", path, "x") == first
