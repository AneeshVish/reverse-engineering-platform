"""BCC uprobe sniffer for SSL_write / SSL_read (Linux MVP)."""

import logging
import sys
import threading
from typing import Callable, Optional

logger = logging.getLogger(__name__)

MAX_BUF_SIZE = 400

_BPF_C = r"""
#include <uapi/linux/ptrace.h>

#define MAX_BUF_SIZE 400
#define TASK_COMM_LEN 16

struct ssl_data_t {
    u32 pid;
    u32 uid;
    u64 timestamp_ns;
    u32 len;
    char comm[TASK_COMM_LEN];
    char buf[MAX_BUF_SIZE];
};

BPF_PERF_OUTPUT(ssl_events);

int probe_SSL_write_enter(struct pt_regs *ctx, void *ssl, void *buf, int num) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 uid = bpf_get_current_uid_gid();
    struct ssl_data_t data = {};
    data.pid = pid;
    data.uid = uid;
    data.timestamp_ns = bpf_ktime_get_ns();
    data.len = num > MAX_BUF_SIZE ? MAX_BUF_SIZE : num;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user(&data.buf, data.len, buf);
    ssl_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int probe_SSL_read_exit(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 uid = bpf_get_current_uid_gid();
    int ret = PT_REGS_RC(ctx);
    if (ret <= 0) return 0;
    struct ssl_data_t data = {};
    data.pid = pid;
    data.uid = uid;
    data.timestamp_ns = bpf_ktime_get_ns();
    data.len = ret > MAX_BUF_SIZE ? MAX_BUF_SIZE : ret;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    void *buf = (void *)PT_REGS_PARM2(ctx);
    bpf_probe_read_user(&data.buf, data.len, buf);
    ssl_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""


def available() -> bool:
    from src.core import capabilities
    return capabilities.probe_ebpf_support()


class eBPFSniffer:
    """Attach uprobes to SSL_write/SSL_read and stream events to a callback."""

    def __init__(self, target_so_path: str = "", on_event: Optional[Callable] = None):
        from src.core.ebpf_capture.lib_resolver import resolve_ssl_library
        self.target_so = target_so_path or resolve_ssl_library()
        self.on_event = on_event
        self._bpf = None
        self._thread = None
        self._stop = threading.Event()

    def start(self) -> bool:
        if sys.platform != "linux":
            logger.warning("eBPF capture requires Linux")
            return False
        if not available():
            logger.warning("eBPF not available (root + bcc required)")
            return False
        try:
            from bcc import BPF
            self._bpf = BPF(text=_BPF_C)
            self._bpf.attach_uprobe(
                name=self.target_so, sym="SSL_write", fn_name="probe_SSL_write_enter"
            )
            self._bpf.attach_uprobe(
                name=self.target_so, sym="SSL_read", fn_name="probe_SSL_read_exit"
            )
            self._stop.clear()
            self._thread = threading.Thread(target=self._poll, daemon=True)
            self._thread.start()
            return True
        except Exception as e:
            logger.error("eBPF sniffer start failed: %s", e)
            return False

    def _poll(self):
        def _cb(cpu, data, size):
            import ctypes
            class S(ctypes.Structure):
                _fields_ = [
                    ("pid", ctypes.c_uint32),
                    ("uid", ctypes.c_uint32),
                    ("timestamp_ns", ctypes.c_uint64),
                    ("len", ctypes.c_uint32),
                    ("comm", ctypes.c_char * 16),
                    ("buf", ctypes.c_char * MAX_BUF_SIZE),
                ]
            evt = ctypes.cast(data, ctypes.POINTER(S)).contents
            payload = bytes(evt.buf[: evt.len])
            rec = {
                "pid": evt.pid,
                "uid": evt.uid,
                "timestamp_ns": evt.timestamp_ns,
                "len": evt.len,
                "comm": evt.comm.decode("utf-8", errors="replace").strip("\x00"),
                "payload": payload,
                "sym": "SSL_write",
                "ssl_lib": self.target_so,
            }
            if self.on_event:
                self.on_event(rec)

        self._bpf["ssl_events"].open_perf_buffer(_cb)
        while not self._stop.is_set():
            try:
                self._bpf.perf_buffer_poll(timeout=500)
            except Exception:
                break

    def stop(self):
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)
        self._bpf = None

    def export_pcapng_hint(self) -> str:
        """Phase D: PCAPNG export placeholder."""
        return "PCAPNG export requires ringbuf migration (Phase D)"
