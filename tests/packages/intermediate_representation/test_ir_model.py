"""IR tests: metadata ordering, type construction, symbol construction."""

from __future__ import annotations

from reveng_intermediate_representation import (
    ArrayType,
    Binding,
    EnumType,
    FunctionSignature,
    MetadataBag,
    PointerType,
    PrimitiveType,
    StructureType,
    Symbol,
    SymbolKind,
    Visibility,
)


def test_metadata_is_key_sorted() -> None:
    bag = MetadataBag.of({"z": 1, "a": 2, "m": 3})
    assert bag.keys() == ("a", "m", "z")


def test_metadata_ordering_is_insertion_independent() -> None:
    a = MetadataBag.of({"x": 1, "y": 2})
    b = MetadataBag.of({"y": 2, "x": 1})
    assert a == b
    assert a.items() == b.items()


def test_metadata_is_immutable_derivation() -> None:
    base = MetadataBag.of({"a": 1})
    derived = base.with_value("b", 2)
    assert not base.contains("b")
    assert derived.get("b") == 2


def test_empty_metadata() -> None:
    assert len(MetadataBag.of()) == 0
    assert len(MetadataBag.of(None)) == 0


def test_primitive_type() -> None:
    t = PrimitiveType(name="int32", bit_width=32)
    assert t.type_kind == "PrimitiveType"
    assert t.bit_width == 32


def test_composite_types() -> None:
    inner = PrimitiveType(name="u8", bit_width=8)
    ptr = PointerType(name="u8*", pointee=inner)
    arr = ArrayType(name="u8[4]", element=inner, count=4)
    struct = StructureType(name="S", fields=(("a", inner), ("b", ptr)))
    enum = EnumType(name="E", members=(("A", 0), ("B", 1)))
    sig = FunctionSignature(name="fn", return_type=inner, parameters=(ptr, arr), variadic=True)
    assert ptr.pointee is inner
    assert arr.count == 4
    assert struct.fields[1][1] is ptr
    assert enum.members == (("A", 0), ("B", 1))
    assert sig.variadic and len(sig.parameters) == 2


def test_symbol_construction() -> None:
    sym = Symbol(
        name="main",
        kind=SymbolKind.FUNCTION,
        visibility=Visibility.PUBLIC,
        binding=Binding.GLOBAL,
    )
    assert sym.kind is SymbolKind.FUNCTION
    assert sym.visibility is Visibility.PUBLIC
    assert sym.binding is Binding.GLOBAL
