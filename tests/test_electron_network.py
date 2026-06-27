"""Tests for Electron asar extraction and network intelligence."""

import json
import os
import struct
import pytest

from src.core import asar, electron, network_intel


def _make_asar(tmp_path, files):
    """Build a minimal valid asar from {name: bytes}. Returns the path."""
    # Concatenate file data; build the header with offsets.
    blobs = b""
    entries = {}
    for name, data in files.items():
        entries[name] = {"size": len(data), "offset": str(len(blobs))}
        blobs += data
    header = json.dumps({"files": entries}).encode("utf-8")
    # Pickle: [uint32=4][uint32=hdr_size][uint32=obj_size][uint32=json_len][json...]
    json_len = len(header)
    obj_size = json_len + 4
    hdr_size = obj_size + 4
    head = struct.pack("<4I", 4, hdr_size, obj_size, json_len) + header
    # data base = 8 + hdr_size  => pad header region accordingly
    pad = (8 + hdr_size) - len(head)
    blob = head + (b"\x00" * max(0, pad)) + blobs
    p = tmp_path / "app.asar"
    p.write_bytes(blob)
    return str(p)


def test_asar_roundtrip(tmp_path):
    src = {"index.js": b"console.log('hi')", "pkg/data.json": b'{"a":1}'}
    apath = _make_asar(tmp_path, src)
    assert asar.is_asar(apath)
    names = dict(asar.list_asar(apath))
    assert "index.js" in names and names["index.js"] == len(src["index.js"])
    dest = tmp_path / "out"
    n = asar.extract_asar(apath, str(dest))
    assert n == 2
    assert (dest / "index.js").read_bytes() == src["index.js"]
    assert (dest / "pkg" / "data.json").read_bytes() == src["pkg/data.json"]


def test_is_asar_rejects_plain_file(tmp_path):
    p = tmp_path / "x.bin"
    p.write_bytes(b"not an asar at all, just bytes")
    assert asar.is_asar(str(p)) is False


def test_electron_detection_and_extract(tmp_path):
    app = tmp_path / "Demo.app"
    res = app / "Contents" / "Resources"
    res.mkdir(parents=True)
    apath = _make_asar(res, {"main.js": b"// app source\nrequire('discord')"})
    os.rename(apath, res / "app.asar")
    assert electron.is_electron_app(str(app))
    assert electron.find_enclosing_app(str(res / "app.asar")) == str(app)
    dest = tmp_path / "src"
    assert electron.extract_source(str(app), str(dest)) == 1
    assert (dest / "main.js").exists()


def test_hosts_from_urls():
    urls = ["https://discord.com/api/v9", "wss://gateway.discord.gg/?v=9",
            "http://cdn.discordapp.com/x.png", "not a url"]
    hosts = network_intel.hosts_from_urls(urls)
    assert "discord.com" in hosts
    assert "gateway.discord.gg" in hosts
    assert "cdn.discordapp.com" in hosts


def test_local_ips_returns_list():
    ips = network_intel.local_ips()
    assert isinstance(ips, list)
    assert all("." in ip for ip in ips)


def test_resolve_localhost():
    ips = network_intel.resolve_host("localhost", timeout=2.0)
    assert any(ip.startswith("127.") or ip == "::1" for ip in ips) or ips == []


def test_format_network_intel():
    txt = network_intel.format_network_intel(
        ["192.168.0.5"], {"discord.com": ["1.2.3.4"]})
    assert "192.168.0.5" in txt
    assert "discord.com" in txt and "1.2.3.4" in txt
