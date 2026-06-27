"""Tests for live traffic capture (controller + secret extraction)."""

import os

from src.core import traffic_capture as tc
from scripts.mitm_capture_addon import extract_secrets


def test_capture_env_sets_proxy_and_ca():
    env = tc.capture_env(8080, ca="/tmp/ca.pem")
    assert env["HTTPS_PROXY"] == "http://127.0.0.1:8080"
    assert env["HTTP_PROXY"] == "http://127.0.0.1:8080"
    # CA trust pointed at our cert for Node/Python/curl without system install.
    assert env["NODE_EXTRA_CA_CERTS"] == "/tmp/ca.pem"
    assert env["REQUESTS_CA_BUNDLE"] == "/tmp/ca.pem"
    assert env["SSL_CERT_FILE"] == "/tmp/ca.pem"


def test_available_and_ca_are_bools():
    assert isinstance(tc.available(), bool)
    assert isinstance(tc.ca_exists(), bool)


def test_resolve_launch_target_app_bundle(tmp_path):
    app = tmp_path / "Demo.app"
    macos = app / "Contents" / "MacOS"
    macos.mkdir(parents=True)
    (macos / "Demo").write_bytes(b"\x7fELF")
    import plistlib
    with open(app / "Contents" / "Info.plist", "wb") as f:
        plistlib.dump({"CFBundleExecutable": "Demo"}, f)
    exe = tc.resolve_launch_target(str(app))
    assert exe.endswith("Contents/MacOS/Demo")


def test_resolve_launch_target_plain(tmp_path):
    p = tmp_path / "tool"
    p.write_text("x")
    assert tc.resolve_launch_target(str(p)) == str(p)


def test_extract_secrets_finds_tokens_and_keys():
    text = (
        "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1In0.s1gn4tur3abcdef\n"
        "x-api-key: AKIAIOSFODNN7EXAMPLE\n"
        '{"client_secret": "abcDEF123456ghijkl", "password": "hunter2hunter2"}\n'
        "google=AIzaSyA1234567890abcdefghijklmnopqrstuv\n"
    )
    found = extract_secrets(text)
    types = {s["type"] for s in found}
    assert "Bearer token" in types
    assert "JWT" in types
    assert "AWS access key" in types
    assert "Google API key" in types
    assert any("client_secret" in s["value"] or "password" in s["value"]
               for s in found if s["type"] == "OAuth/secret param")


def test_extract_secrets_empty():
    assert extract_secrets("") == []
    assert extract_secrets("nothing sensitive here at all") == []
