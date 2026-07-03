"""Unified RE session — resign + mitm + Frida orchestration."""

from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Callable


@dataclass
class RESessionState:
    target: str = ""
    instrumented_copy: str = ""
    proxy_port: int = 0
    mitm_running: bool = False
    frida_attached: bool = False
    app_pid: int = 0
    errors: List[str] = field(default_factory=list)


class RESession:
    """Orchestrate re-sign, network capture, and Frida for one engagement."""

    def __init__(self, on_event: Callable = None):
        self.state = RESessionState()
        self.on_event = on_event
        self._proxy_proc = None
        self._cap_file = None
        self._frida = None
        self._app_proc = None

    def prepare(self, app_path: str) -> RESessionState:
        from src.core import resign, traffic_capture as tc
        self.state.target = app_path
        if app_path.endswith(".app") or ".app/" in app_path:
            result = resign.prepare_instrumentable_copy(app_path)
            if result.get("ok"):
                self.state.instrumented_copy = result.get("copy_path", "")
            else:
                self.state.errors.append(result.get("message", "Re-sign failed"))
        return self.state

    def start_capture(self, port: int = 0) -> int:
        from src.core import traffic_capture as tc
        import tempfile
        self._cap_file = tempfile.NamedTemporaryFile(
            prefix="re_capture_", suffix=".jsonl", delete=False).name
        self.state.proxy_port = port or tc.pick_port()
        self._proxy_proc = tc.start_proxy(self.state.proxy_port, self._cap_file)
        self.state.mitm_running = self._proxy_proc is not None
        return self.state.proxy_port if self.state.mitm_running else 0

    def launch(self, target: str = "") -> bool:
        from src.core import traffic_capture as tc
        exe = target or self.state.instrumented_copy or self.state.target
        if not exe:
            self.state.errors.append("No launch target")
            return False
        self._app_proc = tc.launch_app(exe, self.state.proxy_port)
        if self._app_proc:
            self.state.app_pid = self._app_proc.pid
            return True
        self.state.errors.append("Launch failed")
        return False

    def attach_frida(self, pid: int = 0) -> bool:
        from src.core import runtime_crypto as rc
        from src.core import capabilities
        if not capabilities.package_available("frida"):
            self.state.errors.append("Frida not available")
            return False
        self._frida = rc.RuntimeCryptoCapture(on_event=self.on_event, follow_children=True)
        target_pid = pid or self.state.app_pid
        if target_pid:
            try:
                self._frida.attach(target_pid)
                self.state.frida_attached = True
                return True
            except Exception as e:
                self.state.errors.append(f"Frida attach: {e}")
        return False

    def stop(self):
        from src.core import traffic_capture as tc
        if self._proxy_proc:
            try:
                self._proxy_proc.terminate()
            except Exception:
                pass
            self._proxy_proc = None
        if self._frida:
            try:
                self._frida.detach()
            except Exception:
                pass
        if self._app_proc:
            try:
                self._app_proc.terminate()
            except Exception:
                pass
        self.state.mitm_running = False
        self.state.frida_attached = False

    def summary(self) -> str:
        s = self.state
        lines = ["RE SESSION", "=" * 40,
                 f"Target: {s.target}",
                 f"Instrumented: {s.instrumented_copy or '—'}",
                 f"Proxy: {'running :' + str(s.proxy_port) if s.mitm_running else 'stopped'}",
                 f"Frida: {'attached' if s.frida_attached else 'not attached'}",
                 f"App PID: {s.app_pid or '—'}"]
        for e in s.errors:
            lines.append(f"  ! {e}")
        return "\n".join(lines)
