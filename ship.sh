#!/bin/bash
# One-shot verify + commit + push for the endpoint-evidence layer.
# Run once:  bash ship.sh    (delete this file afterward if you like)
set -e
cd "/Users/ani/Projects/Reverse Engg/reverse-engineering-platform"

echo "== 1/4 compile =="
.venv/bin/python -m py_compile \
  src/core/tls_identity.py src/core/tracker_list.py src/core/pii_classify.py \
  src/core/endpoint_correlation.py src/core/traffic_capture.py \
  src/gui/network_capture_panel.py src/gui/main_window.py
echo "   compile OK"

echo "== 2/4 full test suite =="
QT_QPA_PLATFORM=offscreen .venv/bin/python -m pytest -q
# (set -e aborts here if any test fails — nothing gets committed)

echo "== 3/4 commit =="
git add src/core/tls_identity.py src/core/tracker_list.py src/core/pii_classify.py \
  src/core/endpoint_correlation.py src/core/traffic_capture.py \
  src/gui/network_capture_panel.py src/gui/main_window.py \
  tests/test_evidence_layer.py
git commit -m "Endpoint evidence layer (4 claims) + one-click auto-capture

Proves WHO/WHAT/WHY behind an endpoint address, not just the address:
- tls_identity: TLS handshake -> cert (CN/SAN/issuer/validity) + DNS + IP-WHOIS
  + domain-WHOIS -> ownership proof-card with an independently-checkable verdict
- tracker_list: known third-party tracker/analytics classifier
- pii_classify: flags the actual PII fields in captured request bodies
- endpoint_correlation: static endpoints x live sockets -> confirmed/predicted/live-only

Network Capture reworked: auto-starts on tab open, single hidden port, full
call+message view, new detail tabs (User Data / Server Proof / Static<->Live).
Already-running apps need one explicit relaunch click. Adds test_evidence_layer.py.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"

echo "== 4/4 push =="
git push origin main
echo "DONE — shipped."
