#!/usr/bin/env python3
"""Chatty demo client — a CONSTANT stream of decryptable HTTPS calls so the Network
Capture panel lights up every feature at once: live calls, request messages,
secrets/tokens, the User Data (PII) tab, the TRACKER flag, and the Server Proof.

It honors the capture proxy automatically: `requests` reads HTTPS_PROXY and
REQUESTS_CA_BUNDLE from the environment, which the capture panel sets when it
launches a target. So: in Network Capture, Browse -> select this file -> Start
Capture, and watch the table fill.

Everything sent is SYNTHETIC (fake email / device-id / token) to public test APIs.
Real servers (github/ipify/httpbin) so the TLS ownership proof works too.
"""
import random
import time
import uuid

import requests  # honors HTTPS_PROXY + REQUESTS_CA_BUNDLE from the environment

TARGETS = [
    ("POST", "https://httpbin.org/post"),
    ("GET", "https://api.github.com/repos/python/cpython"),
    ("GET", "https://api.ipify.org?format=json"),
    ("POST", "https://httpbin.org/anything"),
]
# A real known-tracker endpoint so the TRACKER flag fires (benign collect hit).
TRACKER = ("POST", "https://www.google-analytics.com/collect")


def synthetic_body():
    """Fake user data — exercises the PII / secrets detection (nothing real)."""
    return {
        "email": f"user{random.randint(1, 999)}@example.com",
        "device_id": str(uuid.uuid4()),
        "advertising_id": str(uuid.uuid4()),
        "access_token": "demo_" + uuid.uuid4().hex,
        "lat": round(random.uniform(-90, 90), 5),
        "lon": round(random.uniform(-180, 180), 5),
        "event": random.choice(["play", "pause", "login", "scroll"]),
    }


def main():
    print("Chatty demo client running — constant HTTPS traffic. Ctrl-C to stop.")
    n = 0
    while True:
        method, url = random.choice(TARGETS + [TRACKER])
        try:
            if method == "POST":
                r = requests.post(url, json=synthetic_body(), timeout=10)
            else:
                r = requests.get(url, timeout=10)
            n += 1
            print(f"[{n}] {method} {url} -> {r.status_code}")
        except Exception as e:
            print(f"[!] {method} {url}: {e}")
        time.sleep(1.2)


if __name__ == "__main__":
    main()
