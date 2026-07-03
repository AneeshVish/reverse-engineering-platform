"""Architecture keyword taxonomy for client-side intelligence extraction."""

import re
from typing import List, Dict, Tuple

# Categories and keywords (from RED TEAM plan)
LEXICON: Dict[str, List[str]] = {
    "service_mesh": ["envoy", "istio", "linkerd", "consul", "service-mesh", "x-envoy"],
    "rpc": ["grpc", "grpc-web", "protobuf", "proto", "thrift", "avro"],
    "gateway": ["kong", "nginx", "traefik", "api-gateway", "apigw"],
    "datastore": ["postgres", "postgresql", "mysql", "mariadb", "mongodb", "mongo",
                  "redis", "clickhouse", "sqlite", "dynamodb", "cassandra", "elasticsearch"],
    "messaging": ["kafka", "rabbitmq", "sqs", "pubsub", "nats", "pulsar"],
    "storage": ["s3", "gcs", "azure-blob", "minio", "blob-storage"],
    "ml_inference": ["inference", "embedding", "vector", "llm", "openai", "anthropic",
                     "completion", "tokenizer", "model-server"],
    "orchestration": ["kubernetes", "k8s", "docker", "ecs", "lambda", "cloudrun"],
    "observability": ["datadog", "sentry", "newrelic", "prometheus", "grafana",
                      "opentelemetry", "traceparent", "jaeger", "zipkin"],
    "auth": ["oauth", "oidc", "saml", "jwt", "bearer", "auth0", "cognito"],
    "internal": ["staging", "internal", "debug", "admin", "backdoor", "dev-only",
                 "feature-flag", "feature_flag", "enableInternal"],
    "scheduling": ["scheduler", "cron", "celery", "sidekiq", "bull", "queue"],
}

# Compile patterns for whole-word-ish matching in source text
_COMPILED: Dict[str, List[Tuple[str, re.Pattern]]] = {}


def _patterns():
    global _COMPILED
    if _COMPILED:
        return _COMPILED
    for cat, words in LEXICON.items():
        _COMPILED[cat] = []
        for w in words:
            pat = re.compile(r"(?<![a-z0-9_-])" + re.escape(w) + r"(?![a-z0-9_-])", re.I)
            _COMPILED[cat].append((w, pat))
    return _COMPILED


def scan_text(text: str, source: str = "") -> List[Dict]:
    """Return [{category, keyword, source, context}] for all lexicon hits."""
    if not text:
        return []
    hits = []
    seen = set()
    for cat, patterns in _patterns().items():
        for keyword, pat in patterns:
            for m in pat.finditer(text):
                key = (cat, keyword.lower(), source)
                if key in seen:
                    continue
                seen.add(key)
                start = max(0, m.start() - 40)
                end = min(len(text), m.end() + 40)
                ctx = text[start:end].replace("\n", " ").strip()
                hits.append({
                    "category": cat,
                    "keyword": keyword,
                    "source": source,
                    "context": ctx,
                })
    return hits


def scan_bytes(data: bytes, source: str = "") -> List[Dict]:
    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        text = ""
    return scan_text(text, source)


def categories_found(hits: List[Dict]) -> List[str]:
    return sorted({h["category"] for h in hits})
