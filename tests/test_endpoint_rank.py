"""Tests for evidence-based endpoint ranking (Task 1: filter real vs. noise).

Uses the same kinds of strings a real minified Electron bundle produces (the
Claude.app case): namespace URIs, spec/doc links, the Apple signing chain, cloud
metadata, test fixtures — plus one genuinely real, live-confirmed API host.
"""

from src.core import endpoint_rank as er
from src.intelligence.endpoint_detector import NetworkEndpoint as NE


def _url(u):
    return NE(0, u, 0.95, "URL")


def test_host_of_normalizes():
    assert er.host_of("https://api.anthropic.com/v1/messages") == "api.anthropic.com"
    assert er.host_of("HTTP://Example.COM/") == "example.com"
    assert er.host_of("user@host.com:443") == "host.com"


def test_namespace_and_doc_links_are_noise():
    eps = [
        _url("http://www.w3.org/2000/svg"),
        _url("http://ns.adobe.com/xdp/"),
        _url("https://json-schema.org/draft/2020-12/schema"),
        _url("https://github.com/websockets/ws/issues/1202"),
        _url("https://tc39.es/ecma262/#sec-isarray"),
    ]
    ranked = {r.host: r.tier for r in er.rank(eps)}
    assert ranked["www.w3.org"] == "namespace"
    assert ranked["ns.adobe.com"] == "namespace"
    assert ranked["json-schema.org"] == "library-ref"
    assert ranked["github.com"] == "library-ref"
    assert ranked["tc39.es"] == "library-ref"


def test_pki_and_local_and_test_hosts():
    eps = [
        _url("http://certs.apple.com/devidg2.der"),
        _url("http://ocsp.apple.com/ocsp03"),
        _url("http://127.0.0.1:40342/metadata/identity/oauth2/token"),
        _url("http://169.254.169.254/metadata/instance"),
        _url("http://example.com"),
    ]
    ranked = {r.host: r.tier for r in er.rank(eps)}
    assert ranked["certs.apple.com"] == "pki"
    assert ranked["ocsp.apple.com"] == "pki"
    assert ranked["127.0.0.1"] == "local"
    assert ranked["169.254.169.254"] == "local"
    assert ranked["example.com"] == "test/malformed"


def test_live_confirmation_promotes_real_server():
    eps = [_url("https://api.anthropic.com/v1/messages")]
    resolved = {"api.anthropic.com": ["160.79.104.10"]}
    # Same IP shows up in the live socket table -> confirmed-live (strongest tier).
    ranked = er.rank(eps, live_ips=["160.79.104.10"], resolved=resolved)
    top = ranked[0]
    assert top.host == "api.anthropic.com"
    assert top.tier == "confirmed-live"


def test_resolves_to_real_server_without_live():
    eps = [_url("https://api.anthropic.com/v1/messages")]
    resolved = {"api.anthropic.com": ["160.79.104.10"]}
    ranked = {r.host: r.tier for r in er.rank(eps, resolved=resolved)}
    assert ranked["api.anthropic.com"] == "real-server"


def test_live_only_host_appears():
    ranked = {r.host: r.tier for r in er.rank([], live_hosts=["telemetry.example-cdn.net"])}
    assert ranked["telemetry.example-cdn.net"] == "live-only"


def test_same_host_links_collapse_to_one_entry():
    # 30 spec links to the SAME host should become a single ranked entry.
    eps = [_url(f"https://tc39.es/ecma262/#sec-{i}") for i in range(30)]
    ranked = er.rank(eps)
    assert sum(1 for r in ranked if r.host == "tc39.es") == 1


def test_format_leads_with_real_and_collapses_noise():
    eps = [_url("https://api.anthropic.com/v1/messages")]
    # Many DISTINCT library-doc hosts -> previewed and collapsed, not all dumped.
    eps += [_url(f"https://sub{i}.tc39.es/x") for i in range(20)]
    ranked = er.rank(eps, live_ips=["160.79.104.10"],
                     resolved={"api.anthropic.com": ["160.79.104.10"]})
    out = er.format_ranked(ranked)
    assert "CONFIRMED LIVE" in out
    assert "api.anthropic.com" in out
    assert "collapsed as noise" in out
