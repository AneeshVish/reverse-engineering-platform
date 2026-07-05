"""Runtime Crypto Capture — read plaintext at the endpoint via Frida hooks.

The legitimate, on-device version of "defeat the encryption". It does NOT break
AES or reverse SHA (impossible). Instead it attaches to a process YOU control and
hooks that process's OWN cryptography calls, capturing the key / IV / plaintext as
the app decrypts its own data. This is standard dynamic reverse engineering — the
same technique used for malware analysis and app security assessment.

SCOPE / AUTHORIZATION:
  - This instruments a LOCAL process you spawn or own on this machine.
  - It reads what the target itself decrypts here; it cannot decrypt a third
    party's data remotely and is not a remote exploit.
  - Use only on software you are authorized to analyze (your own app, a sample,
    or a target you have written permission to test).

Requires the `frida` package (`pip install frida`). Degrades gracefully if absent
so the rest of the app keeps working.
"""

try:
    import frida
except Exception:  # ImportError, or frida core load failure
    frida = None


def available():
    """True if Frida is importable (the capability is usable)."""
    return frida is not None


# Frida JS agent: hook the common crypto primitives AND the TLS read/write
# boundary, then stream what passes through them. Crypto fields are capped small
# to stay light; TLS payloads get a larger cap so a full HTTP request line +
# headers + the start of a JSON body survive (the true size is always in `len`).
#
# SSL_write/SSL_read are where an HTTPS client hands its request/response in
# CLEARTEXT to the TLS layer — hooking them yields the plaintext API traffic
# (bodies, auth tokens, user data) without breaking TLS. In Electron the network
# client (undici/Chromium net) lives in a CHILD process, so the Python side must
# follow children and inject this agent into each of them (see follow_children).
AGENT_JS = r"""
(function () {
  function grab(ptr, n) {
    try {
      if (ptr.isNull() || n <= 0) return null;
      var buf = Memory.readByteArray(ptr, n);
      return buf ? Array.from(new Uint8Array(buf)) : null;
    } catch (e) { return null; }
  }
  var CAP = 256;        // crypto key/iv/data fields
  var TLS_CAP = 8192;   // TLS plaintext (headers + JSON body head)

  // Apple CommonCrypto:
  // CCCrypt(op, alg, options, key, keyLen, iv, dataIn, dataInLen, dataOut, ...)
  var p = Module.findExportByName(null, 'CCCrypt');
  if (p) Interceptor.attach(p, { onEnter: function (a) {
    var keyLen = a[4].toInt32(), dataLen = a[7].toInt32();
    send({ api: 'CCCrypt', op: a[0].toInt32() === 1 ? 'decrypt' : 'encrypt',
           key: grab(a[3], keyLen), iv: grab(a[5], 16),
           data: grab(a[6], Math.min(dataLen, CAP)), len: dataLen });
  }});

  // OpenSSL / BoringSSL: EVP_DecryptUpdate(ctx, out, *outl, in, inl)
  ['EVP_DecryptUpdate', 'EVP_EncryptUpdate'].forEach(function (name) {
    var f = Module.findExportByName(null, name);
    if (f) Interceptor.attach(f, { onEnter: function (a) {
      var inl = a[4].toInt32();
      send({ api: name, op: name.indexOf('Decrypt') >= 0 ? 'decrypt' : 'encrypt',
             data: grab(a[3], Math.min(inl, CAP)), len: inl });
    }});
  });

  // SHA-256 input (you can't reverse the hash, but you can read what was hashed):
  // CC_SHA256(data, len, md)
  var s = Module.findExportByName(null, 'CC_SHA256');
  if (s) Interceptor.attach(s, { onEnter: function (a) {
    var len = a[1].toInt32();
    send({ api: 'CC_SHA256', op: 'hash-input', data: grab(a[0], Math.min(len, CAP)), len: len });
  }});

  // --- TLS plaintext boundary (BoringSSL / OpenSSL) -----------------------
  // int SSL_write(SSL *ssl, const void *buf, int num)  -> plaintext being SENT
  var w = Module.findExportByName(null, 'SSL_write');
  if (w) Interceptor.attach(w, { onEnter: function (a) {
    var n = a[2].toInt32();
    send({ api: 'SSL_write', op: 'tls-send',
           data: grab(a[1], Math.min(n, TLS_CAP)), len: n });
  }});

  // int SSL_read(SSL *ssl, void *buf, int num) -> plaintext RECEIVED; the buffer
  // is only filled by the time the call returns, and the return value is the
  // real byte count, so we read on the way OUT.
  var r = Module.findExportByName(null, 'SSL_read');
  if (r) Interceptor.attach(r, {
    onEnter: function (a) { this.buf = a[1]; },
    onLeave: function (ret) {
      var n = ret.toInt32();
      if (n > 0) send({ api: 'SSL_read', op: 'tls-recv',
                        data: grab(this.buf, Math.min(n, TLS_CAP)), len: n });
    }
  });
})();
"""


class RuntimeCryptoCapture:
    """Attach Frida to a local process (and, for multi-process apps like Electron,
    its child processes) and collect crypto- and TLS-call events.

    `follow_children` is essential for Electron/Chromium targets: the process you
    spawn is the main/browser process, but the HTTPS client (undici / Chromium
    net) runs in a child (utility/renderer) process. With child-gating on, each
    child is held at start, injected with the same agent, then resumed — so the
    TLS plaintext hooks land in the process that actually opens the sockets.
    """

    def __init__(self, on_event=None, follow_children=True):
        self.on_event = on_event
        self.events = []
        self.follow_children = follow_children
        self._device = None
        self._sessions = []   # one per hooked process (main + children)
        self._scripts = []

    def _wire(self, session, pid=None):
        """Inject the agent into one process's session and start streaming."""
        script = session.create_script(AGENT_JS)
        script.on("message", lambda message, data, _pid=pid: self._on_message(message, _pid))
        script.load()
        self._sessions.append(session)
        self._scripts.append(script)

    def _on_message(self, message, pid=None):
        if message.get("type") == "send":
            evt = message.get("payload")
            if isinstance(evt, dict):
                if pid is not None:
                    evt.setdefault("pid", pid)
                self.events.append(evt)
                if self.on_event:
                    self.on_event(evt)
        elif message.get("type") == "error":
            evt = {"api": "agent-error", "op": message.get("description", "error")}
            if pid is not None:
                evt["pid"] = pid
            self.events.append(evt)
            if self.on_event:
                self.on_event(evt)

    def _on_child(self, child):
        """A gated child appeared: attach + inject before letting it run."""
        pid = getattr(child, "pid", None)
        try:
            session = self._device.attach(pid)
            if self.follow_children:
                try:
                    session.enable_child_gating()
                except Exception:
                    pass   # grandchild gating is best-effort
            self._wire(session, pid=pid)
        except Exception as e:
            self._on_message({"type": "error", "description": f"child {pid} attach failed: {e}"}, pid)
        finally:
            try:
                self._device.resume(pid)
            except Exception:
                pass

    def spawn(self, program):
        """Spawn `program` (path or argv list) suspended, hook it (and its
        children if follow_children), then resume."""
        if frida is None:
            raise RuntimeError("frida not installed — run: pip install frida")
        self._device = frida.get_local_device()
        if self.follow_children:
            self._device.on("child-added", self._on_child)
        argv = program if isinstance(program, list) else [program]
        pid = self._device.spawn(argv)
        session = self._device.attach(pid)
        if self.follow_children:
            try:
                session.enable_child_gating()
            except Exception:
                pass
        self._wire(session, pid=pid)
        try:
            load_unpin_scripts(session)
        except Exception:
            pass
        self._device.resume(pid)
        return pid

    def attach(self, target):
        """Attach to an already-running process by name or PID.

        NOTE: attach can only hook children that are spawned AFTER this call
        (via child-gating). Children already running are missed — for full
        coverage of an Electron app, prefer spawn (cold start)."""
        if frida is None:
            raise RuntimeError("frida not installed — run: pip install frida")
        self._device = frida.get_local_device()
        if self.follow_children:
            self._device.on("child-added", self._on_child)
        session = self._device.attach(target)
        if self.follow_children:
            try:
                session.enable_child_gating()
            except Exception:
                pass
        self._wire(session, pid=target if isinstance(target, int) else None)
        return target

    def stop(self):
        for script in self._scripts:
            try:
                script.unload()
            except Exception:
                pass
        for session in self._sessions:
            try:
                session.detach()
            except Exception:
                pass
        self._scripts = []
        self._sessions = []


def load_unpin_scripts(session, assets_dir=None):
    """Load OkHttp/TrustKit/TrustManager unpin scripts from assets/frida/."""
    import os
    if assets_dir is None:
        from src.utils.paths import project_root
        assets_dir = os.path.join(project_root(), "assets", "frida")
    names = ("okhttp_unpin.js", "trustkit_unpin.js", "trustmanager_override.js")
    loaded = []
    for name in names:
        path = os.path.join(assets_dir, name)
        if os.path.isfile(path):
            try:
                with open(path, encoding="utf-8") as f:
                    session.create_script(f.read()).load()
                loaded.append(name)
            except Exception:
                pass
    return loaded


def _hexdump(byte_list):
    b = bytes(byte_list)
    return b.hex()


def _ascii(byte_list):
    return "".join(chr(c) if 32 <= c < 127 else "." for c in byte_list)


def format_event(evt):
    """Render one captured crypto/TLS event as readable text (key/iv/plaintext)."""
    api = evt.get("api", "?")
    op = evt.get("op", "")
    pid = evt.get("pid")
    head = f"[{api}] {op}".rstrip()
    if pid is not None:
        head += f"  (pid {pid})"
    lines = [head]
    if evt.get("key"):
        lines.append(f"  key ({len(evt['key'])} bytes): {_hexdump(evt['key'])}")
    if evt.get("iv"):
        lines.append(f"  iv:  {_hexdump(evt['iv'])}")
    if evt.get("data"):
        lines.append(f"  data: {_hexdump(evt['data'])}")
        lines.append(f"  data (ascii): {_ascii(evt['data'])}")
    if evt.get("len") is not None:
        lines.append(f"  length: {evt['len']} bytes")
    return "\n".join(lines)


def format_capture(events):
    """Render a whole capture session."""
    if not events:
        return ("No crypto/TLS calls captured yet. The target may not have run a "
                "hooked function yet, or its crypto/TLS symbols aren't exported where "
                "we look (CommonCrypto / OpenSSL / BoringSSL — including SSL_write / "
                "SSL_read — are covered). For Electron apps, cold-start via Spawn so "
                "child processes are followed.")
    header = [f"RUNTIME CRYPTO + TLS CAPTURE — {len(events)} call(s) intercepted",
              "(key / IV / plaintext + TLS request/response read at the endpoint)", ""]
    return "\n".join(header + [format_event(e) for e in events])
