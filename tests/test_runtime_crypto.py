"""Tests for Runtime Crypto Capture formatting + capability gate.

The live Frida attach/spawn path needs a real target and is verified manually on an
owned process; CI exercises only the pure logic (no instrumentation, no frida import
required at runtime since `available()` tolerates its absence).
"""

from src.core import runtime_crypto as rc


def test_available_returns_bool():
    assert isinstance(rc.available(), bool)


def test_format_event_renders_key_iv_plaintext():
    evt = {
        "api": "CCCrypt", "op": "decrypt",
        "key": list(b"\x00\x11\x22\x33"),
        "iv": list(b"\xaa" * 4),
        "data": list(b'{"token":"live_x"}'),
        "len": 18,
    }
    out = rc.format_event(evt)
    assert "[CCCrypt] decrypt" in out
    assert "key (4 bytes): 00112233" in out
    assert "iv:  aaaaaaaa" in out
    assert '{"token":"live_x"}' in out          # plaintext recovered, ascii view
    assert "length: 18 bytes" in out


def test_format_capture_empty_is_honest():
    out = rc.format_capture([])
    assert "No crypto/TLS calls captured" in out
    assert "CommonCrypto" in out
    assert "SSL_write" in out          # TLS boundary is advertised as covered


def test_agent_hooks_tls_read_and_write():
    # The injected agent must hook the TLS plaintext boundary, not just crypto.
    assert "SSL_write" in rc.AGENT_JS
    assert "SSL_read" in rc.AGENT_JS
    assert "onLeave" in rc.AGENT_JS    # SSL_read plaintext is read on the way out


def test_format_event_renders_tls_plaintext_with_pid():
    evt = {
        "api": "SSL_write", "op": "tls-send", "pid": 4321,
        "data": list(b"POST /v1/messages HTTP/1.1\r\nauthorization: Bearer sk-ant"),
        "len": 512,
    }
    out = rc.format_event(evt)
    assert "[SSL_write] tls-send" in out
    assert "(pid 4321)" in out
    assert "POST /v1/messages HTTP/1.1" in out   # plaintext request line recovered
    assert "length: 512 bytes" in out


def test_format_capture_multiple():
    events = [
        {"api": "EVP_DecryptUpdate", "op": "decrypt", "data": list(b"hello"), "len": 5},
        {"api": "CC_SHA256", "op": "hash-input", "data": list(b"pw"), "len": 2},
    ]
    out = rc.format_capture(events)
    assert "2 call(s) intercepted" in out
    assert "EVP_DecryptUpdate" in out and "CC_SHA256" in out


def test_capture_object_constructs_without_frida():
    # Constructing the controller must never require frida to be installed.
    cap = rc.RuntimeCryptoCapture(on_event=lambda e: None)
    assert cap.events == []


# --- orchestration: spawn + child-following, with a fake Frida device ------
# Frida can't attach in CI, so we stub the device/session/script to prove the
# Python side enables child-gating, injects the agent into children, tags events
# with their pid, and forwards them.

class _FakeScript:
    def __init__(self):
        self._cb = None
        self.loaded = False
        self.unloaded = False

    def on(self, sig, cb):
        if sig == "message":
            self._cb = cb

    def load(self):
        self.loaded = True

    def unload(self):
        self.unloaded = True

    def emit_send(self, payload):
        self._cb({"type": "send", "payload": payload}, None)


class _FakeSession:
    def __init__(self):
        self.scripts = []
        self.child_gating = False
        self.detached = False

    def create_script(self, js):
        s = _FakeScript()
        self.scripts.append(s)
        return s

    def enable_child_gating(self):
        self.child_gating = True

    def detach(self):
        self.detached = True


class _FakeChild:
    def __init__(self, pid):
        self.pid = pid


class _FakeDevice:
    def __init__(self):
        self.sessions = {}
        self.resumed = []
        self._child_cb = None
        self._next_pid = 1000

    def on(self, sig, cb):
        if sig == "child-added":
            self._child_cb = cb

    def spawn(self, argv):
        self._next_pid += 1
        return self._next_pid

    def attach(self, target):
        s = _FakeSession()
        self.sessions[target] = s
        return s

    def resume(self, pid):
        self.resumed.append(pid)

    def emit_child(self, pid):
        self._child_cb(_FakeChild(pid))


class _FakeFrida:
    def __init__(self):
        self.device = _FakeDevice()

    def get_local_device(self):
        return self.device


def test_spawn_enables_child_gating_follows_children_and_tags_pid(monkeypatch):
    fake = _FakeFrida()
    monkeypatch.setattr(rc, "frida", fake)

    events = []
    cap = rc.RuntimeCryptoCapture(on_event=events.append)
    pid = cap.spawn(["/Applications/Claude.app/Contents/MacOS/Claude"])

    # Main process was hooked and gated, then resumed.
    assert fake.device.sessions[pid].child_gating is True
    assert fake.device.sessions[pid].scripts[0].loaded is True
    assert pid in fake.device.resumed

    # A child (e.g. the utility/Node process running undici) spawns: it must be
    # attached, injected, and resumed.
    child_pid = 5555
    fake.device.emit_child(child_pid)
    assert child_pid in fake.device.sessions
    assert fake.device.sessions[child_pid].scripts, "agent not injected into child"
    assert child_pid in fake.device.resumed

    # A TLS event from the CHILD must be forwarded, tagged with the child pid.
    fake.device.sessions[child_pid].scripts[0].emit_send(
        {"api": "SSL_read", "op": "tls-recv", "data": list(b"HTTP/1.1 200 OK"), "len": 15})
    assert any(e.get("pid") == child_pid and e["api"] == "SSL_read" for e in events)

    cap.stop()
    assert fake.device.sessions[pid].scripts[0].unloaded is True


def test_follow_children_disabled_skips_gating(monkeypatch):
    fake = _FakeFrida()
    monkeypatch.setattr(rc, "frida", fake)
    cap = rc.RuntimeCryptoCapture(follow_children=False)
    pid = cap.spawn(["/bin/echo"])
    assert fake.device.sessions[pid].child_gating is False
    assert fake.device._child_cb is None      # no child-added subscription
