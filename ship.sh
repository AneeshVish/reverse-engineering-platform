#!/bin/bash
# One-shot verify + commit + push. Run once:  bash ship.sh
set -e
cd "/Users/ani/Projects/Reverse Engg/reverse-engineering-platform"

echo "== 1/4 compile =="
.venv/bin/python -m py_compile \
  src/core/tls_identity.py src/core/tracker_list.py src/core/pii_classify.py \
  src/core/endpoint_correlation.py src/core/traffic_capture.py \
  src/core/advanced_unpacking.py \
  src/gui/network_capture_panel.py src/gui/full_software_panel.py src/gui/main_window.py
echo "   compile OK"

echo "== 2/4 full test suite =="
QT_QPA_PLATFORM=offscreen .venv/bin/python -m pytest -q
# (set -e aborts here if any test fails — nothing gets committed)

echo "== 3/4 commit =="
git add -A
git commit -m "System-wide capture (trusted CA + system proxy) for real apps; evidence layer; signing-artifact rendering

- traffic_capture: enable/disable_system_capture() — trust the mitmproxy CA and
  set the macOS system proxy via one admin prompt, so ALL non-pinned apps are
  captured & decrypted (including already-running ones), reverting on Stop. This
  is the Charles/Proxyman approach. Pinned apps (Spotify core) still won't decrypt.
- Network Capture panel: 'Capture ALL apps system-wide' toggle, auto-start,
  single hidden port, full call+message view, User Data / Server Proof /
  Static<->Live tabs.
- Endpoint evidence layer (tls_identity, tracker_list, pii_classify,
  endpoint_correlation) wired into Endpoint Detection + capture.
- Reveal Contents: parse code-signing/cert artifacts into readable identities
  (not 'encrypted'); suppress PEiD noise on non-PE; demo_traffic.py demo client.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"

echo "== 4/4 push =="
git push origin main
echo "DONE — shipped."
