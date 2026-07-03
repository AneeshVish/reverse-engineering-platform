"""Tests for architecture lexicon and client intel."""

from src.core import architecture_lexicon as lex
from src.core import client_architecture_intel as cai


def test_lexicon_finds_postgres():
    hits = lex.scan_text("connect to postgres://internal.db/cache", "config.env")
    assert any(h["keyword"] == "postgres" for h in hits)


def test_lexicon_finds_grpc():
    hits = lex.scan_text("import grpc from '@grpc/grpc-js'", "app.js")
    assert any(h["category"] == "rpc" for h in hits)


def test_client_intel_finds_endpoint_in_text(tmp_path):
    f = tmp_path / "api.js"
    f.write_text('const url = "https://api.example.com/v1/messages"; // grpc service')
    intel = cai.analyze_path(str(tmp_path))
    assert intel["files_scanned"] >= 1
    assert any("example.com" in h for h in intel.get("hosts", []))


def test_format_report_empty():
    assert "No architecture" in cai.format_report({})
