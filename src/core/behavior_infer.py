"""Evidence-graded inference of SERVER-SIDE behavior from client-observable traffic.

The hard truth (and the whole design constraint): you cannot *prove* server-side
implementation — "it stores data in PostgreSQL", "it calls an internal
microservice", "it invokes an LLM" — from client traffic alone. A response only
tells you what the server chose to reveal.

So this engine never states such things as facts. Every output is a hypothesis
carrying:
  • a CONFIDENCE tier (OBSERVED > STRONG > MODERATE > WEAK),
  • the exact EVIDENCE it rests on (quoted from the captured flow),
  • CONFOUNDERS — the innocent alternative explanations, and
  • how to RAISE OR FALSIFY it (what independent evidence would move confidence).

OBSERVED means a directly-seen fact (e.g. "responses stream as text/event-stream")
— not an inference. Everything weaker than WEAK is deliberately NOT claimed; it is
listed under "cannot be determined from client traffic" instead. This is what
separates honest reverse engineering from guesswork dressed up as findings.

All detection is PASSIVE: it reads only the flows we already captured. It sends no
crafted probes (that would be active testing and needs explicit authorization).
"""

import re
from dataclasses import dataclass, field
from typing import List

# --- confidence model ------------------------------------------------------

OBSERVED = "OBSERVED"      # a directly observed fact, not an inference
STRONG = "STRONG"          # signature is near-unique to the claim
MODERATE = "MODERATE"      # consistent + corroborated, but alternatives exist
WEAK = "WEAK"              # suggestive only; common/ambiguous signal

_RANK = {OBSERVED: 0, STRONG: 1, MODERATE: 2, WEAK: 3}


@dataclass
class Evidence:
    detail: str            # exact, quoted observation
    source: str = ""       # where it came from (host/path or "response header")


@dataclass
class Inference:
    category: str          # e.g. "Architecture tier", "Datastore", "Inference backend"
    claim: str             # the hypothesis, phrased as a hypothesis
    confidence: str
    evidence: List[Evidence] = field(default_factory=list)
    confounders: List[str] = field(default_factory=list)
    raise_confidence: List[str] = field(default_factory=list)


# --- helpers ---------------------------------------------------------------

def _resp_headers_ci(flow):
    """Response headers as a case-insensitive {lower: (orig, value)} map."""
    out = {}
    for k, v in (flow.get("resp_headers") or {}).items():
        out[k.lower()] = (k, v)
    return out


def _req_headers_ci(flow):
    out = {}
    for k, v in (flow.get("req_headers") or {}).items():
        out[k.lower()] = (k, v)
    return out


def _text(s, n=4000):
    s = "" if s is None else str(s)
    return s if len(s) <= n else s[:n]


def _host_of(flow):
    return flow.get("host", "") or ""


def _first(flows, predicate):
    for f in flows:
        if predicate(f):
            return f
    return None


# --- signature tables (validated against vendor docs / specs) --------------

# Reverse proxy / API gateway / CDN / mesh: header -> (provider, what it proves).
# Presence proves the response passed through that layer to a SEPARATE origin —
# i.e. at least a 2-tier (edge/proxy -> origin) topology.
_PROXY_HEADER_SIGS = [
    ("x-envoy-upstream-service-time", "Envoy proxy",
     "Envoy timed a separate upstream host handling the request. Envoy is the "
     "data plane of service meshes (Istio, AWS App Mesh) and Google Cloud "
     "(GKE/Cloud Run)."),
    ("x-envoy-decorator-operation", "Envoy / Istio mesh",
     "Istio/Envoy mesh-internal routing metadata leaked to the client."),
    ("x-kong-upstream-latency", "Kong API gateway",
     "Kong measured a separate upstream service's response time."),
    ("x-kong-proxy-latency", "Kong API gateway",
     "Kong API gateway proxied the request to an upstream service."),
    ("x-kong-request-id", "Kong API gateway",
     "Kong API gateway assigned this request an ID."),
    ("cf-ray", "Cloudflare edge",
     "Cloudflare's edge network fronted the request; the origin is behind it."),
    ("x-served-by", "Fastly/Varnish CDN",
     "A Fastly/Varnish edge node served the response."),
    ("x-timer", "Fastly CDN", "Fastly edge timing metadata."),
    ("x-amz-cf-id", "AWS CloudFront",
     "AWS CloudFront CDN fronted the request."),
    ("x-amzn-requestid", "AWS API Gateway / Lambda",
     "An AWS API Gateway / Lambda request ID was returned."),
    ("x-amz-apigw-id", "AWS API Gateway",
     "AWS API Gateway handled the request."),
    ("x-amzn-trace-id", "AWS load balancer / X-Ray",
     "AWS ALB/X-Ray attached a trace ID."),
    ("x-azure-ref", "Azure Front Door",
     "Azure Front Door / CDN fronted the request."),
    ("x-msedge-ref", "Azure Front Door", "Azure edge reference id."),
    ("x-vercel-id", "Vercel edge",
     "Vercel's edge network handled the request."),
    ("fly-request-id", "Fly.io", "Fly.io edge/proxy handled the request."),
]

# Server / X-Powered-By tokens -> (technology, kind, confidence, note).
# Server: nginx/apache are often just reverse proxies, so they're weaker signals
# about the *application* than an explicit X-Powered-By.
_SERVER_TOKEN_SIGS = [
    ("gunicorn", "Gunicorn (Python WSGI app server)", STRONG),
    ("werkzeug", "Werkzeug — Flask's dev server (Python)", STRONG),
    ("uvicorn", "Uvicorn (Python ASGI app server)", STRONG),
    ("kestrel", "Kestrel (ASP.NET Core app server)", STRONG),
    ("puma", "Puma (Ruby app server)", STRONG),
    ("passenger", "Phusion Passenger (Ruby/Python app server)", STRONG),
    ("microsoft-iis", "Microsoft IIS", STRONG),
    ("coyote", "Apache Tomcat (Java servlet container)", STRONG),
    ("jetty", "Eclipse Jetty (Java servlet container)", STRONG),
    ("tomcat", "Apache Tomcat (Java servlet container)", STRONG),
    ("litespeed", "LiteSpeed web server", STRONG),
    ("caddy", "Caddy web server", STRONG),
    ("nginx", "nginx (web server / reverse proxy)", WEAK),
    ("apache", "Apache httpd (web server / reverse proxy)", WEAK),
]

_POWERED_BY_SIGS = [
    ("express", "Express.js (Node.js)"),
    ("php", "PHP"),
    ("asp.net", "ASP.NET"),
    ("next.js", "Next.js (Node.js)"),
    ("servlet", "Java Servlet container"),
]

# Session-cookie name -> framework family (near-unique naming conventions).
_COOKIE_FRAMEWORK_SIGS = [
    ("connect.sid", "Express.js / connect session (Node.js)"),
    ("phpsessid", "PHP"),
    ("jsessionid", "Java servlet container (Tomcat/Jetty/JBoss)"),
    ("asp.net_sessionid", "ASP.NET"),
    (".aspnetcore", "ASP.NET Core"),
    ("csrftoken", "Django (Python)"),
    ("laravel_session", "Laravel (PHP)"),
    ("_rails_session", "Ruby on Rails"),
]

# Datastore error signatures. Presence in a response body is STRONG, near-direct
# evidence of the engine — production servers try to suppress these, so a leak is
# meaningful. (regex, engine)
_DB_ERROR_SIGS = [
    (r"SQLSTATE\[", "a SQL database (SQLSTATE error)"),
    (r"PG::|PostgreSQL|violates (?:unique|foreign key) constraint|invalid input syntax for",
     "PostgreSQL"),
    (r"You have an error in your SQL syntax|MySqlException|com\.mysql|MariaDB", "MySQL/MariaDB"),
    (r"ORA-\d{5}", "Oracle Database"),
    (r"Microsoft SQL Server|System\.Data\.SqlClient|Msg \d+, Level \d+", "Microsoft SQL Server"),
    (r"MongoError|E11000 duplicate key", "MongoDB"),
    (r"SQLITE_[A-Z]+|sqlite3\.", "SQLite"),
    (r"WRONGTYPE Operation|MISCONF Redis|NOAUTH Authentication required", "Redis"),
]

# Tracing/correlation headers -> (system, is_distributed_tracing).
_TRACING_HEADER_SIGS = [
    ("traceparent", "W3C Trace Context (distributed tracing)", True),
    ("tracestate", "W3C Trace Context (distributed tracing)", True),
    ("x-b3-traceid", "Zipkin/B3 (distributed tracing)", True),
    ("b3", "Zipkin/B3 (distributed tracing)", True),
    ("uber-trace-id", "Jaeger (distributed tracing)", True),
    ("x-cloud-trace-context", "Google Cloud Trace (distributed tracing)", True),
    ("x-request-id", "request correlation id", False),
    ("x-correlation-id", "request correlation id", False),
    ("request-id", "request correlation id", False),
]

_SERVER_TIMING_SUBSYSTEMS = {
    "db": "a database query phase", "sql": "a SQL query phase",
    "cache": "a cache lookup phase", "redis": "a Redis phase",
    "memcache": "a Memcache phase", "render": "a template/render phase",
    "app": "application compute", "origin": "origin-server compute",
    "cdn-cache": "a CDN cache phase", "es": "an Elasticsearch phase",
    "search": "a search phase", "auth": "an authentication phase",
    "upstream": "an upstream service call",
}


# --- detectors -------------------------------------------------------------

def detect_proxy_gateway_mesh(flows):
    out = []
    seen = {}
    for f in flows:
        rh = _resp_headers_ci(f)
        for header, provider, meaning in _PROXY_HEADER_SIGS:
            if header in rh and provider not in seen:
                orig, val = rh[header]
                seen[provider] = Inference(
                    category="Architecture tier",
                    claim=f"Traffic is fronted by {provider}; the application origin "
                          "sits behind it (multi-tier, not a single flat server).",
                    confidence=STRONG,
                    evidence=[Evidence(f"{orig}: {_text(val, 120)}", f"{_host_of(f)} response header")],
                    confounders=[
                        f"{provider} can front a single monolith as easily as many "
                        "microservices — this proves a proxy→origin hop, not the "
                        "number of backend services.",
                        "The header may be added by a shared platform, not chosen by "
                        "this specific application team."],
                    raise_confidence=[meaning,
                        "Look for multiple distinct upstream identifiers, mesh headers "
                        "(x-envoy-decorator-operation), or per-service trace spans."])
    out.extend(seen.values())
    return out


def detect_web_stack(flows):
    out = []
    claimed = set()
    for f in flows:
        rh = _resp_headers_ci(f)
        host = _host_of(f)
        # Server:
        if "server" in rh:
            _, sval = rh["server"]
            low = sval.lower()
            for token, tech, conf in _SERVER_TOKEN_SIGS:
                if token in low and tech not in claimed:
                    claimed.add(tech)
                    inf = Inference(
                        category="Web stack",
                        claim=f"The server software is likely {tech}.",
                        confidence=conf,
                        evidence=[Evidence(f"Server: {_text(sval, 120)}", f"{host} response header")],
                        confounders=["The Server header is trivially spoofable and is "
                                     "often set by a fronting proxy, not the app server."])
                    if conf == WEAK:
                        inf.confounders.append(
                            f"{tech} is very commonly a reverse proxy — the real "
                            "application server behind it may be something else.")
                    inf.raise_confidence = ["Corroborate with X-Powered-By, a framework "
                                            "cookie, or a framework-specific error page."]
                    out.append(inf)
                    break
        # X-Powered-By:
        if "x-powered-by" in rh:
            _, pval = rh["x-powered-by"]
            low = pval.lower()
            for token, tech in _POWERED_BY_SIGS:
                if token in low and tech not in claimed:
                    claimed.add(tech)
                    out.append(Inference(
                        category="Web stack",
                        claim=f"The application framework/runtime is {tech}.",
                        confidence=STRONG,
                        evidence=[Evidence(f"X-Powered-By: {_text(pval, 120)}", f"{host} response header")],
                        confounders=["X-Powered-By can be spoofed or left at a default; "
                                     "it names the framework, not the app's behavior."],
                        raise_confidence=["Corroborate with a session-cookie name or "
                                          "framework error page."]))
                    break
        for hdr, tech in [("x-aspnet-version", "ASP.NET"),
                          ("x-aspnetmvc-version", "ASP.NET MVC"),
                          ("x-runtime", "a Rack/Rails app (X-Runtime middleware)")]:
            if hdr in rh and tech not in claimed:
                claimed.add(tech)
                orig, val = rh[hdr]
                out.append(Inference(
                    category="Web stack",
                    claim=f"The application is built on {tech}.",
                    confidence=MODERATE,
                    evidence=[Evidence(f"{orig}: {_text(val, 80)}", f"{host} response header")],
                    confounders=["Version/runtime headers can be spoofed or proxied."],
                    raise_confidence=["Corroborate with a framework cookie or error page."]))
        # Session cookies (Set-Cookie).
        setck = ""
        for lk, (orig, val) in rh.items():
            if lk == "set-cookie":
                setck = val
        cookie_hay = (setck + " " + (rh.get("set-cookie", ("", ""))[1] if "set-cookie" in rh else "")).lower()
        for name, family in _COOKIE_FRAMEWORK_SIGS:
            key = f"cookie:{family}"
            if name in cookie_hay and key not in claimed:
                claimed.add(key)
                out.append(Inference(
                    category="Web stack",
                    claim=f"The backend uses {family} (session-cookie naming convention).",
                    confidence=STRONG,
                    evidence=[Evidence(f"Set-Cookie contains '{name}'", f"{host} response header")],
                    confounders=["Cookie names can be customized or reused across "
                                 "frameworks, though defaults are highly indicative."],
                    raise_confidence=["Corroborate with Server / X-Powered-By or an error page."]))
    return out


def detect_tracing(flows):
    out = []
    claimed = set()
    for f in flows:
        rh = _resp_headers_ci(f)
        host = _host_of(f)
        for header, system, distributed in _TRACING_HEADER_SIGS:
            if header in rh and system not in claimed:
                claimed.add(system)
                orig, val = rh[header]
                if distributed:
                    out.append(Inference(
                        category="Distributed architecture",
                        claim="The backend runs distributed tracing, which is used to "
                              "follow a request across MULTIPLE internal services — "
                              "strong sign of a multi-service architecture.",
                        confidence=MODERATE,
                        evidence=[Evidence(f"{orig}: {_text(val, 120)}  ({system})",
                                           f"{host} response header")],
                        confounders=["Tracing can be deployed on a single service too; "
                                     "its presence proves the capability, not the count "
                                     "of services."],
                        raise_confidence=["Find the same trace/correlation ID across "
                                          "requests to different hosts, or per-service "
                                          "spans in server-timing."]))
                else:
                    out.append(Inference(
                        category="Distributed architecture",
                        claim="The backend stamps per-request correlation IDs — "
                              "consistent with centralized request logging/observability.",
                        confidence=WEAK,
                        evidence=[Evidence(f"{orig}: {_text(val, 120)}",
                                           f"{host} response header")],
                        confounders=["Correlation IDs are used by single services too; "
                                     "this is not by itself evidence of microservices."],
                        raise_confidence=["Correlate the same ID across multiple hosts."]))
    return out


def detect_server_timing_subsystems(flows):
    out = []
    seen_names = {}
    for f in flows:
        rh = _resp_headers_ci(f)
        if "server-timing" not in rh:
            continue
        _, val = rh["server-timing"]
        host = _host_of(f)
        for metric in val.split(","):
            name = metric.strip().split(";")[0].strip().lower()
            if name in _SERVER_TIMING_SUBSYSTEMS and name not in seen_names:
                seen_names[name] = (host, metric.strip())
    for name, (host, raw) in seen_names.items():
        meaning = _SERVER_TIMING_SUBSYSTEMS[name]
        out.append(Inference(
            category="Internal subsystems (server-declared)",
            claim=f"The server itself reports spending time in {meaning} "
                  f"(Server-Timing metric '{name}').",
            confidence=MODERATE,
            evidence=[Evidence(f"Server-Timing: …{_text(raw, 80)}…", f"{host} response header")],
            confounders=["Server-Timing metric names are free-form tokens chosen by the "
                         "developer — the name is a strong hint but not a guarantee of "
                         "the actual subsystem.",
                         "It confirms a phase existed, not which product implements it "
                         "(e.g. 'db' doesn't reveal Postgres vs MySQL)."],
            raise_confidence=["Combine with an error-message leak that names the exact "
                              "engine."]))
    return out


def detect_datastore_errors(flows):
    out = []
    claimed = set()
    for f in flows:
        body = _text(f.get("resp_body"), 20000)
        if not body:
            continue
        host = _host_of(f)
        for pattern, engine in _DB_ERROR_SIGS:
            if engine in claimed:
                continue
            m = re.search(pattern, body)
            if m:
                claimed.add(engine)
                snippet = body[max(0, m.start() - 20): m.end() + 40].replace("\n", " ")
                out.append(Inference(
                    category="Datastore",
                    claim=f"The backend uses {engine} — a database error signature "
                          "leaked into a response body.",
                    confidence=STRONG,
                    evidence=[Evidence(f"…{_text(snippet, 140)}…",
                                       f"{host} {f.get('path','')} (status {f.get('status')})")],
                    confounders=["The error text could be quoted/proxied from elsewhere, "
                                 "or an ORM/abstraction could sit in front of a different "
                                 "store — but a native engine error is strong evidence.",
                                 "It does not reveal the schema, host, or that data is "
                                 "persisted (vs a transient/validation query)."],
                    raise_confidence=["Reproduce with a controlled malformed input "
                                      "(ACTIVE test — only with explicit authorization)."]))
    return out


def detect_inference_backend(flows):
    out = []
    # Token-metered rate limits: near-unique to LLM/inference APIs.
    for f in flows:
        rh = _resp_headers_ci(f)
        token_meters = [orig for lk, (orig, _) in rh.items()
                        if "ratelimit" in lk and "token" in lk]
        if token_meters:
            out.append(Inference(
                category="Inference backend",
                claim="This endpoint fronts a token-metered generative/LLM inference "
                      "service (usage is billed/limited per token).",
                confidence=STRONG,
                evidence=[Evidence("token rate-limit headers: " + ", ".join(sorted(set(token_meters))[:4]),
                                   f"{_host_of(f)} response header")],
                confounders=["Token metering is characteristic of LLM APIs, but a "
                             "provider could reuse 'token' terminology for another "
                             "quota; corroborate with usage fields."],
                raise_confidence=["Confirm token-usage fields in the body "
                                  "(prompt/completion/total tokens)."]))
            break
    # Token-usage / generation fields in JSON bodies.
    usage_pat = re.compile(
        r'"(prompt_tokens|completion_tokens|total_tokens|input_tokens|output_tokens|'
        r'finish_reason|stop_reason|logprobs)"')
    hit = _first(flows, lambda f: usage_pat.search(_text(f.get("resp_body"), 20000) or ""))
    if hit:
        m = usage_pat.search(_text(hit.get("resp_body"), 20000))
        out.append(Inference(
            category="Inference backend",
            claim="This endpoint returns generative-model output metadata — consistent "
                  "with an LLM/text-generation inference service.",
            confidence=STRONG,
            evidence=[Evidence(f"response body contains {m.group(0)}",
                               f"{_host_of(hit)} {hit.get('path','')}")],
            confounders=["Field names could be mimicked; but this vocabulary "
                         "(prompt/completion tokens, finish_reason) is specific to "
                         "generative inference."],
            raise_confidence=["Observe streamed generation (text/event-stream) and "
                              "latency scaling with output length."]))
    # SSE streaming (weaker on its own).
    sse = _first(flows, lambda f: "text/event-stream" in
                 (_resp_headers_ci(f).get("content-type", ("", ""))[1].lower()))
    if sse:
        out.append(Inference(
            category="Inference backend",
            claim="Responses stream incrementally (Server-Sent Events) — the pattern "
                  "generative/LLM endpoints use to emit tokens as they are produced.",
            confidence=MODERATE if out else WEAK,
            evidence=[Evidence("Content-Type: text/event-stream",
                               f"{_host_of(sse)} {sse.get('path','')}")],
            confounders=["SSE is also used for progress feeds, logs, and notifications — "
                         "streaming alone is not proof of an LLM."],
            raise_confidence=["Combine with token-usage fields or token-metered limits."]))
    return out


def detect_api_style(flows):
    out = []
    # GraphQL
    gq = _first(flows, lambda f: "graphql" in (f.get("path", "") or "").lower()
                or ('"query"' in (_text(f.get("req_body"), 4000) or "")
                    and ("mutation" in _text(f.get("req_body"), 4000)
                         or "__typename" in _text(f.get("resp_body"), 4000))))
    if gq:
        out.append(Inference(
            category="API style",
            claim="The backend exposes a GraphQL API.",
            confidence=STRONG,
            evidence=[Evidence(f"path/query indicates GraphQL",
                               f"{_host_of(gq)} {gq.get('path','')}")],
            confounders=["A GraphQL gateway can still sit in front of REST/microservices "
                         "— the query language doesn't reveal the backing services."],
            raise_confidence=["Run an introspection query (active) to map the schema."]))
    # gRPC
    grpc = _first(flows, lambda f: "grpc" in (_resp_headers_ci(f).get("content-type", ("", ""))[1].lower())
                  or "grpc-status" in _resp_headers_ci(f))
    if grpc:
        out.append(Inference(
            category="API style",
            claim="The endpoint speaks gRPC (an RPC protocol typical of internal "
                  "microservice communication).",
            confidence=STRONG,
            evidence=[Evidence("gRPC content-type / grpc-status header",
                               f"{_host_of(grpc)} {grpc.get('path','')}")],
            confounders=["gRPC is a transport choice; it doesn't prove how many services "
                         "are behind it."]))
    return out


def detect_async_processing(flows):
    out = []
    for f in flows:
        if str(f.get("status")) == "202":
            rh = _resp_headers_ci(f)
            if "location" in rh or "retry-after" in rh:
                out.append(Inference(
                    category="Processing model",
                    claim="The endpoint accepts work asynchronously (202 + polling "
                          "location) — implying a background worker/queue behind it.",
                    confidence=MODERATE,
                    evidence=[Evidence(f"HTTP 202 with "
                                       f"{'Location' if 'location' in rh else 'Retry-After'}",
                                       f"{_host_of(f)} {f.get('path','')}")],
                    confounders=["202 can be returned without a real queue; it indicates "
                                 "deferred processing, not a specific queue technology."],
                    raise_confidence=["Poll the location and observe state transitions."]))
                break
    return out


def _decode_jwt_claims(token):
    """Best-effort decode of a JWT payload (NO verification) to read iss/aud."""
    import base64
    import json
    parts = token.split(".")
    if len(parts) < 2:
        return {}
    try:
        pad = parts[1] + "=" * (-len(parts[1]) % 4)
        return json.loads(base64.urlsafe_b64decode(pad).decode("utf-8", "replace"))
    except Exception:
        return {}


def detect_auth_topology(flows):
    out = []
    # OAuth/OIDC/SAML redirect to a DIFFERENT host = delegated identity provider.
    for f in flows:
        status = str(f.get("status"))
        if status.startswith("3"):
            rh = _resp_headers_ci(f)
            loc = rh.get("location", ("", ""))[1]
            if loc and any(k in loc.lower() for k in
                           ("oauth", "authorize", "openid", "/saml", "sso")):
                m = re.search(r"https?://([^/]+)", loc)
                idp = m.group(1) if m else "a separate host"
                out.append(Inference(
                    category="Auth topology",
                    claim=f"Authentication is delegated to a separate identity provider "
                          f"({idp}).",
                    confidence=STRONG,
                    evidence=[Evidence(f"{status} redirect Location → {_text(loc, 120)}",
                                       f"{_host_of(f)} {f.get('path','')}")],
                    confounders=["The IdP may belong to the same org (self-hosted SSO) "
                                 "rather than a third party."]))
                break
    # JWT issuer/audience from tokens we captured (decode only, no verify).
    for f in flows:
        auth = _req_headers_ci(f).get("authorization", ("", ""))[1]
        m = re.search(r"[Bb]earer\s+(eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)", auth)
        if m:
            claims = _decode_jwt_claims(m.group(1))
            iss, aud = claims.get("iss"), claims.get("aud")
            if iss or aud:
                out.append(Inference(
                    category="Auth topology",
                    claim="Access tokens are issued by a token/identity service"
                          + (f" '{iss}'" if iss else "")
                          + (f" for audience '{aud}'" if aud else "") + ".",
                    confidence=MODERATE,
                    evidence=[Evidence("decoded (unverified) JWT 'iss'/'aud' claims",
                                       f"{_host_of(f)} request Authorization")],
                    confounders=["iss/aud are self-declared token claims; the issuer may "
                                 "be the same service, not a separate one."],
                    raise_confidence=["Observe a distinct token-issuance endpoint / host."]))
                break
    return out


def correlate_cross_host(flows):
    """Same correlation/trace ID seen on two DIFFERENT hosts => one distributed system."""
    out = []
    id_headers = ("x-request-id", "request-id", "x-correlation-id", "traceparent",
                  "x-amzn-trace-id")
    seen = {}   # id_value -> set(hosts)
    for f in flows:
        rh = _resp_headers_ci(f)
        host = _host_of(f)
        for h in id_headers:
            if h in rh:
                val = rh[h][1]
                # For traceparent, the trace-id is the shared part across hops.
                if h == "traceparent":
                    bits = val.split("-")
                    val = bits[1] if len(bits) > 1 else val
                seen.setdefault(val, set()).add(host)
    for val, hosts in seen.items():
        if len(hosts) >= 2:
            out.append(Inference(
                category="Distributed architecture",
                claim="Two different hosts shared one correlation/trace ID — concrete "
                      "evidence they are parts of the SAME distributed system.",
                confidence=STRONG,
                evidence=[Evidence(f"id {_text(val, 40)} seen on: " + ", ".join(sorted(hosts)),
                                   "cross-host correlation")],
                confounders=["Requires the ID to be genuinely shared (not coincidentally "
                             "equal); trace IDs are effectively unique so this is robust."]))
            break
    return out


DETECTORS = [
    detect_proxy_gateway_mesh, detect_web_stack, detect_tracing,
    detect_server_timing_subsystems, detect_datastore_errors,
    detect_inference_backend, detect_api_style, detect_async_processing,
    detect_auth_topology, correlate_cross_host,
]


def infer(flows):
    """Run every detector over the captured flows. Returns [Inference] sorted by
    confidence then category."""
    flows = flows or []
    results = []
    for det in DETECTORS:
        try:
            results.extend(det(flows))
        except Exception:
            continue   # a broken detector must never sink the whole analysis
    results.sort(key=lambda i: (_RANK.get(i.confidence, 9), i.category, i.claim))
    return results


# Things that are fundamentally NOT decidable from client traffic — shown verbatim
# so the tool never lets a demo imply more than it proved.
CANNOT_DETERMINE = [
    "Whether (and where) data is persisted — a DB error can leak the engine, but "
    "not that this request wrote/stored anything, nor the schema or host.",
    "The exact database product when there is no error leak or server-declared "
    "timing (e.g. Postgres vs MySQL is indistinguishable from a normal 200).",
    "The number, names, or boundaries of internal microservices.",
    "Whether the endpoint forwards to another cluster/region, or which one.",
    "Server-side business logic, or what happens after a 200 is returned.",
    "Any of the above with certainty from headers alone — headers are spoofable "
    "and are often set by fronting proxies, not the application.",
]


def _badge(conf):
    return {OBSERVED: "[OBSERVED]", STRONG: "[STRONG] ", MODERATE: "[MODERATE]",
            WEAK: "[WEAK]    "}.get(conf, f"[{conf}]")


def format_report(flows):
    """Client-facing, honesty-first rendering of the inference results."""
    infs = infer(flows)
    lines = ["SERVER-SIDE BEHAVIOR — EVIDENCE-GRADED INFERENCE", ""]
    lines.append("Server-side implementation cannot be PROVEN from client traffic. Every")
    lines.append("item below is a hypothesis with a confidence tier, the evidence it rests")
    lines.append("on, the innocent alternative explanations (confounders), and how to raise")
    lines.append("or falsify it. Nothing here should be presented to a client as a fact.")
    lines.append("")
    lines.append("Confidence:  OBSERVED = directly seen · STRONG = near-unique signature ·")
    lines.append("             MODERATE = corroborated but ambiguous · WEAK = suggestive only")
    lines.append("=" * 74)

    if not infs:
        lines.append("")
        lines.append("No server-side behavior signals inferred yet. Capture more traffic "
                     "(exercise the app) — headers, error responses, and streaming bodies "
                     "are where these signals appear.")
    else:
        current = None
        for i in infs:
            if i.category != current:
                current = i.category
                lines.append("")
                lines.append(f"## {current}")
            lines.append("")
            lines.append(f"{_badge(i.confidence)}  {i.claim}")
            for e in i.evidence:
                src = f"  ({e.source})" if e.source else ""
                lines.append(f"    evidence: {e.detail}{src}")
            for c in i.confounders:
                lines.append(f"    confounder: {c}")
            for r in i.raise_confidence:
                lines.append(f"    to confirm: {r}")

    lines.append("")
    lines.append("=" * 74)
    lines.append("CANNOT BE DETERMINED FROM CLIENT TRAFFIC (be explicit with clients)")
    lines.append("=" * 74)
    for c in CANNOT_DETERMINE:
        lines.append(f"  • {c}")
    return "\n".join(lines)
