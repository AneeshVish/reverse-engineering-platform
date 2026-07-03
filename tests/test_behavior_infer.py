"""Tests for the evidence-graded server-side behavior inference engine.

The engine's core promise is honesty: correct signatures, correct confidence
tiers, confounders always attached, and an explicit "cannot be determined"
section. These tests lock that promise in.
"""

from src.core import behavior_infer as bi


def _flow(host="api.x.com", path="/v1", status=200, req_headers=None,
          resp_headers=None, req_body="", resp_body=""):
    return {"host": host, "path": path, "status": status,
            "req_headers": req_headers or {}, "resp_headers": resp_headers or {},
            "req_body": req_body, "resp_body": resp_body,
            "url": f"https://{host}{path}", "method": "POST"}


def _by_category(infs, category):
    return [i for i in infs if i.category == category]


# --- proxy / gateway / mesh ------------------------------------------------

def test_envoy_upstream_time_infers_multi_tier():
    infs = bi.infer([_flow(resp_headers={"x-envoy-upstream-service-time": "42"})])
    tier = _by_category(infs, "Architecture tier")
    assert tier and "Envoy" in tier[0].claim
    assert tier[0].confidence == bi.STRONG
    # Confounder must temper it: proxy != proven microservices.
    assert any("monolith" in c or "number of backend" in c for c in tier[0].confounders)


def test_kong_gateway_detected():
    infs = bi.infer([_flow(resp_headers={"Via": "kong/3.4.1",
                                         "X-Kong-Upstream-Latency": "6"})])
    tier = _by_category(infs, "Architecture tier")
    assert any("Kong" in i.claim for i in tier)


# --- web stack -------------------------------------------------------------

def test_x_powered_by_express_is_strong():
    infs = bi.infer([_flow(resp_headers={"X-Powered-By": "Express"})])
    ws = _by_category(infs, "Web stack")
    assert ws and "Express" in ws[0].claim and ws[0].confidence == bi.STRONG


def test_bare_nginx_is_only_weak_with_proxy_confounder():
    infs = bi.infer([_flow(resp_headers={"Server": "nginx/1.25.3"})])
    ws = _by_category(infs, "Web stack")
    assert ws and ws[0].confidence == bi.WEAK
    assert any("reverse proxy" in c for c in ws[0].confounders)


def test_session_cookie_reveals_framework():
    infs = bi.infer([_flow(resp_headers={"Set-Cookie": "connect.sid=abc; HttpOnly"})])
    ws = _by_category(infs, "Web stack")
    assert any("Express" in i.claim for i in ws)


# --- datastore error leakage ----------------------------------------------

def test_postgres_error_leak_is_strong():
    body = '{"error":"PG::UniqueViolation: ERROR: duplicate key value violates unique constraint"}'
    infs = bi.infer([_flow(status=500, resp_body=body)])
    ds = _by_category(infs, "Datastore")
    assert ds and "PostgreSQL" in ds[0].claim and ds[0].confidence == bi.STRONG
    # Must NOT overclaim persistence.
    assert any("persisted" in c or "schema" in c for c in ds[0].confounders)


def test_no_db_claim_without_leak():
    infs = bi.infer([_flow(status=200, resp_body='{"ok":true}')])
    assert _by_category(infs, "Datastore") == []


# --- inference backend (LLM) ----------------------------------------------

def test_token_metered_ratelimit_infers_llm_strong():
    infs = bi.infer([_flow(resp_headers={
        "anthropic-ratelimit-tokens-remaining": "1999",
        "anthropic-ratelimit-tokens-limit": "2000"})])
    ib = _by_category(infs, "Inference backend")
    assert ib and any(i.confidence == bi.STRONG for i in ib)


def test_usage_fields_infer_llm():
    body = '{"model":"claude","usage":{"input_tokens":10,"output_tokens":50},"stop_reason":"end_turn"}'
    infs = bi.infer([_flow(resp_body=body)])
    ib = _by_category(infs, "Inference backend")
    assert ib and any("generative" in i.claim.lower() or "llm" in i.claim.lower() for i in ib)


def test_sse_alone_is_not_strong():
    infs = bi.infer([_flow(resp_headers={"Content-Type": "text/event-stream"})])
    ib = _by_category(infs, "Inference backend")
    assert ib and all(i.confidence in (bi.MODERATE, bi.WEAK) for i in ib)


# --- server-timing subsystem decomposition --------------------------------

def test_server_timing_surfaces_db_and_cache_as_moderate():
    infs = bi.infer([_flow(resp_headers={"Server-Timing": "db;dur=53, cache;dur=23.2, app;dur=47"})])
    sub = _by_category(infs, "Internal subsystems (server-declared)")
    claims = " ".join(i.claim for i in sub)
    assert "database query phase" in claims and "cache lookup phase" in claims
    assert all(i.confidence == bi.MODERATE for i in sub)


# --- distributed tracing / correlation ------------------------------------

def test_traceparent_infers_distributed_tracing():
    infs = bi.infer([_flow(resp_headers={
        "traceparent": "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"})])
    da = _by_category(infs, "Distributed architecture")
    assert any("distributed tracing" in i.claim.lower() for i in da)


def test_same_trace_id_across_hosts_is_strong():
    tp = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
    infs = bi.infer([
        _flow(host="a.com", resp_headers={"traceparent": tp}),
        _flow(host="b.com", resp_headers={"traceparent": tp}),
    ])
    da = _by_category(infs, "Distributed architecture")
    assert any(i.confidence == bi.STRONG and "same distributed system" in i.claim.lower()
               for i in da)


# --- auth topology ---------------------------------------------------------

def test_oauth_redirect_to_other_host_detected():
    infs = bi.infer([_flow(status=302, resp_headers={
        "Location": "https://auth.example.com/oauth/authorize?client_id=x"})])
    at = _by_category(infs, "Auth topology")
    assert at and "auth.example.com" in at[0].claim and at[0].confidence == bi.STRONG


# --- honesty guarantees ----------------------------------------------------

def test_every_inference_carries_confounders():
    # A representative mixed capture; every claim must ship its caveats.
    infs = bi.infer([
        _flow(resp_headers={"X-Powered-By": "Express", "Server-Timing": "db;dur=5"}),
        _flow(status=500, resp_body="ORA-00942: table or view does not exist"),
    ])
    assert infs
    for i in infs:
        assert i.confounders, f"inference without confounders: {i.claim}"
        assert i.confidence in (bi.OBSERVED, bi.STRONG, bi.MODERATE, bi.WEAK)


def test_report_is_honest_and_lists_unprovables():
    report = bi.format_report([_flow(resp_headers={"X-Powered-By": "Express"})])
    assert "cannot be PROVEN from client traffic" in report
    assert "CANNOT BE DETERMINED FROM CLIENT TRAFFIC" in report
    assert "microservices" in report.lower()
    assert "[STRONG]" in report


def test_report_handles_empty_capture():
    report = bi.format_report([])
    assert "No server-side behavior signals inferred yet" in report
    assert "CANNOT BE DETERMINED" in report


def test_detector_exception_does_not_sink_analysis(monkeypatch):
    # A broken detector must be swallowed; the rest still run.
    def boom(flows):
        raise RuntimeError("boom")
    monkeypatch.setattr(bi, "DETECTORS", [boom, bi.detect_web_stack])
    infs = bi.infer([_flow(resp_headers={"X-Powered-By": "Express"})])
    assert any("Express" in i.claim for i in infs)
