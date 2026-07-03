"""Network Intelligence — analytics views fed by Live API Capture.

Server evidence, behavior inference, timelines, metrics, region compare, and
active probes live here so the capture tab stays focused on the live flow table.
"""

from PyQt6.QtCore import QTimer, pyqtSignal
from PyQt6.QtWidgets import QLabel, QTabWidget, QVBoxLayout, QWidget

from src.gui.network_capture_panel import (
    BehaviorInferenceView, ServerEvidenceView, _ReportSubTab,
)


class NetworkIntelligencePanel(QWidget):
    """Analytics workbench tab — refresh is driven by NetworkCapturePanel."""

    proofRequested = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._region_samples = []
        self._probe_results = []
        self._proof_cache = {}
        self._static_hosts = []
        self._flows = []
        self._build_ui()
        self._refresh_timer = QTimer(self)
        self._refresh_timer.setSingleShot(True)
        self._refresh_timer.timeout.connect(self._refresh_analytics)

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        title = QLabel("Network Intelligence")
        title.setObjectName("Heading")
        layout.addWidget(title)
        info = QLabel(
            "Evidence-graded server analysis from captured traffic — server proof, "
            "behavior inference, timelines, metrics, region comparison, and probes.")
        info.setObjectName("Dim")
        info.setWordWrap(True)
        layout.addWidget(info)

        self.tabs = QTabWidget()
        self.server_evidence = ServerEvidenceView()
        self.server_evidence.proofRequested.connect(self.proofRequested.emit)
        self.tabs.addTab(self.server_evidence, "Server Evidence")

        self.behavior_view = BehaviorInferenceView()
        self.tabs.addTab(self.behavior_view, "Behavior Inference")

        self.timeline_view = _ReportSubTab(
            "User action → function → request → SSE → UI update (L2 correlation chain).")
        self.tabs.addTab(self.timeline_view, "Behavior Timeline")

        self.request_timeline_view = _ReportSubTab(
            "Shared correlation/trace IDs across requests and streaming responses.")
        self.tabs.addTab(self.request_timeline_view, "Request Timeline")

        self.metrics_view = _ReportSubTab(
            "TTFT, inter-token gaps, rate limits, and retry behavior (measured).")
        self.tabs.addTab(self.metrics_view, "Behavior Metrics")

        self.region_view = _ReportSubTab(
            "Compare endpoint from different regions (requires scope + VPN/manual samples).")
        self.tabs.addTab(self.region_view, "Region Compare")

        self.probes_view = _ReportSubTab(
            "Controlled error probes — rate-limited. Run from the Access Path tab.")
        self.tabs.addTab(self.probes_view, "Active Probes")

        layout.addWidget(self.tabs, 1)

    def bind_capture(self, capture_panel):
        """Wire to a NetworkCapturePanel — called once from main_window."""
        capture_panel.set_intelligence_panel(self)

    def schedule_refresh(self, flows, proof_cache, static_hosts):
        """Coalesce heavy analytics refreshes (called on every new flow)."""
        self._flows = flows or []
        self._proof_cache = proof_cache or {}
        self._static_hosts = list(static_hosts or [])
        self.server_evidence.render(self._flows, self._proof_cache, self._static_hosts)
        self._refresh_timer.start(500)

    def update_proof(self, host, text):
        self._proof_cache[host] = text
        self.server_evidence.update_proof(host, text)

    def clear(self):
        self._flows = []
        self._proof_cache = {}
        self._region_samples = []
        self._probe_results = []
        self.server_evidence.clear()
        self.behavior_view.clear()
        for v in (self.timeline_view, self.request_timeline_view, self.metrics_view,
                  self.region_view, self.probes_view):
            v.clear()

    def add_region_sample(self, sample: dict):
        from src.core import region_probe
        self._region_samples.append(sample)
        comp = region_probe.compare_samples(self._region_samples)
        self.region_view.set_text(region_probe.format_report(comp))

    def add_probe_result(self, result: dict):
        from src.core import controlled_probe as cp
        self._probe_results.append(result)
        self.probes_view.set_text(cp.format_report(
            self._probe_results, cp.analyze_leaks(self._probe_results)))

    def _refresh_analytics(self):
        from src.core import (
            auth_lifecycle, behavior_metrics, behavior_timeline,
            request_correlation, streaming_capture, telemetry_parser,
        )
        flows = self._flows or []
        self.behavior_view.render(flows)
        tl = behavior_timeline.session_timeline()
        tl.merge_flows(flows)
        self.timeline_view.set_text(tl.format_report())
        self.request_timeline_view.set_text(request_correlation.format_report(
            request_correlation.correlate(flows)))
        self.metrics_view.set_text(behavior_metrics.format_report(
            behavior_metrics.measure_flows(flows)))
        auth_text = auth_lifecycle.format_report(auth_lifecycle.analyze_flows(flows))
        if "No auth" not in auth_text:
            self.metrics_view.set_text(self.metrics_view.report.toPlainText() + "\n\n" + auth_text)
        telem = telemetry_parser.analyze_flows(flows)
        telem_text = telemetry_parser.format_report(telem)
        matches = telemetry_parser.correlate_with_api(telem, flows)
        if matches:
            telem_text += "\n\nCorrelated with API flows: " + str(len(matches))
        sse_lines = []
        for f in flows:
            if streaming_capture.is_sse(f):
                sse_lines.append(streaming_capture.format_stream_summary(f))
        if sse_lines:
            telem_text += "\n\nSSE streams:\n" + "\n".join(sse_lines[:10])
        if self.region_view.report.toPlainText() == "":
            self.region_view.set_text(
                "Use Region Compare: enter URL in Access Path tab or add samples via API.")
        if self._probe_results:
            from src.core import controlled_probe as cp
            self.probes_view.set_text(cp.format_report(
                self._probe_results, cp.analyze_leaks(self._probe_results)))
