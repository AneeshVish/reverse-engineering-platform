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


# Frida JS agent: hook the common crypto primitives and stream what passes
# through them. Captures are capped to 256 bytes/field to stay light.
AGENT_JS = r"""
(function () {
  function grab(ptr, n) {
    try {
      if (ptr.isNull() || n <= 0) return null;
      var buf = Memory.readByteArray(ptr, n);
      return buf ? Array.from(new Uint8Array(buf)) : null;
    } catch (e) { return null; }
  }
  var CAP = 256;

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
})();
"""


class RuntimeCryptoCapture:
    """Attach Frida to a local process and collect crypto-call events."""

    def __init__(self, on_event=None):
        self.on_event = on_event
        self.events = []
        self._session = None
        self._script = None

    def _wire(self, session):
        self._session = session
        self._script = session.create_script(AGENT_JS)
        self._script.on("message", self._on_message)
        self._script.load()

    def _on_message(self, message, data):
        if message.get("type") == "send":
            evt = message.get("payload")
            if isinstance(evt, dict):
                self.events.append(evt)
                if self.on_event:
                    self.on_event(evt)
        elif message.get("type") == "error":
            evt = {"api": "agent-error", "op": message.get("description", "error")}
            self.events.append(evt)
            if self.on_event:
                self.on_event(evt)

    def spawn(self, program):
        """Spawn `program` (path or argv list) suspended, hook it, then resume."""
        if frida is None:
            raise RuntimeError("frida not installed — run: pip install frida")
        device = frida.get_local_device()
        argv = program if isinstance(program, list) else [program]
        pid = device.spawn(argv)
        self._wire(device.attach(pid))
        device.resume(pid)
        return pid

    def attach(self, target):
        """Attach to an already-running process by name or PID."""
        if frida is None:
            raise RuntimeError("frida not installed — run: pip install frida")
        device = frida.get_local_device()
        self._wire(device.attach(target))
        return target

    def stop(self):
        try:
            if self._script is not None:
                self._script.unload()
        except Exception:
            pass
        try:
            if self._session is not None:
                self._session.detach()
        except Exception:
            pass
        self._script = None
        self._session = None


def _hexdump(byte_list):
    b = bytes(byte_list)
    return b.hex()


def _ascii(byte_list):
    return "".join(chr(c) if 32 <= c < 127 else "." for c in byte_list)


def format_event(evt):
    """Render one captured crypto event as readable text (key/iv/plaintext)."""
    api = evt.get("api", "?")
    op = evt.get("op", "")
    lines = [f"[{api}] {op}".rstrip()]
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
        return ("No crypto calls captured. The target may not have run a hooked "
                "function yet, or it uses a crypto library we don't hook (CommonCrypto / "
                "OpenSSL / BoringSSL are covered).")
    header = [f"RUNTIME CRYPTO CAPTURE — {len(events)} crypto call(s) intercepted",
              "(key / IV / plaintext read at the endpoint as the target used them)", ""]
    return "\n".join(header + [format_event(e) for e in events])
