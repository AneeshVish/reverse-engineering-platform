"""Access Path tab — discovered + validated server entry points."""

from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import (
    QVBoxLayout, QHBoxLayout, QLabel, QTextEdit, QPushButton, QWidget,
    QLineEdit, QComboBox,
)


class AccessPathPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._candidates = []
        self._flows = []
        self._intel = {}
        self._findings = []
        self._secrets = []
        self._probe_results = []
        self._app_name = ""
        self._user_edited_base = False
        self._last_suggestion = None
        self._validate_timer = QTimer(self)
        self._validate_timer.setSingleShot(True)
        self._validate_timer.timeout.connect(self._validate)
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        hint = QLabel(
            "Discovered access paths from binary analysis and captured traffic. "
            "Base URL auto-fills with a stable API root, then validates automatically.")
        hint.setObjectName("Dim")
        hint.setWordWrap(True)
        layout.addWidget(hint)

        row = QHBoxLayout()
        self.base_url = QLineEdit()
        self.base_url.setPlaceholderText("Stable API base URL (auto-detected)…")
        self.base_url.textEdited.connect(self._on_base_url_edited)
        row.addWidget(self.base_url, 1)
        self.validate_btn = QPushButton("Validate")
        self.validate_btn.clicked.connect(self._validate)
        row.addWidget(self.validate_btn)
        layout.addLayout(row)

        self.auto_hint = QLabel("")
        self.auto_hint.setObjectName("Dim")
        self.auto_hint.setWordWrap(True)
        layout.addWidget(self.auto_hint)

        self.report = QTextEdit()
        self.report.setReadOnly(True)
        layout.addWidget(self.report, 1)

        probe_row = QHBoxLayout()
        self.probe_template = QComboBox()
        from src.core.controlled_probe import PROBE_TEMPLATES
        for tid, desc in PROBE_TEMPLATES:
            self.probe_template.addItem(desc, tid)
        self.run_probe_btn = QPushButton("Run Controlled Probe")
        self.run_probe_btn.clicked.connect(self._run_probe)
        probe_row.addWidget(self.probe_template, 1)
        probe_row.addWidget(self.run_probe_btn)
        layout.addLayout(probe_row)

    def _on_base_url_edited(self, _text):
        self._user_edited_base = True
        self.auto_hint.setText("Manual override — clear the field to resume auto-detection.")

    def set_suggested_base_url(self, suggestion, app_name: str = "") -> bool:
        """Apply auto-detected base URL. Returns True if the field was updated."""
        if suggestion is None:
            return False
        if app_name:
            self._app_name = app_name
        from src.core.api_base_url import is_probe_suitable_url, finalize_suggestion
        suggestion = finalize_suggestion(suggestion, self._app_name or app_name)
        current = self.base_url.text().strip()
        if self._user_edited_base and current:
            if not suggestion.beats(self._last_suggestion):
                return False
        elif current and is_probe_suitable_url(current):
            if (self._last_suggestion and not suggestion.beats(self._last_suggestion)
                    and current == self._last_suggestion.url):
                return False
        elif current and not is_probe_suitable_url(current):
            pass  # always replace bad feature-route URLs
        elif current == suggestion.url:
            self._schedule_validate()
            return False
        self._last_suggestion = suggestion
        self.base_url.blockSignals(True)
        self.base_url.setText(suggestion.url)
        self.base_url.blockSignals(False)
        self._user_edited_base = False
        self.auto_hint.setText(f"Auto ({suggestion.source}): {suggestion.reason}")
        self.refresh()
        self._schedule_validate()
        return True

    def _schedule_validate(self):
        self._validate_timer.start(200)

    def set_context(self, *, findings=None, intel=None, secrets=None, flows=None, app_name=""):
        self._findings = findings or []
        self._intel = intel or {}
        self._secrets = secrets or []
        self._flows = flows or []
        if app_name:
            self._app_name = app_name
        self.refresh()

    def refresh(self):
        from src.core import access_path_engine as ap
        self._candidates = ap.discover(
            vuln_findings=self._findings,
            architecture_intel=self._intel,
            captured_secrets=self._secrets,
            flows=self._flows,
            app_name=self._app_name,
        )
        text = ap.format_report(self._candidates)
        from src.core import staging_session
        diff = staging_session.diff_api_surfaces([], self._flows)
        if diff.get("authenticated_only"):
            text += "\n\n" + staging_session.format_post_auth_report(diff)
        self.report.setPlainText(text)

    def _validate(self):
        from src.core import access_validator, access_path_engine as ap
        from src.core.api_base_url import normalize_probe_url, is_probe_suitable_url
        base = self.base_url.text().strip()
        if not base:
            self.report.setPlainText(
                "Waiting for auto-detect…\n\n"
                "Open Network Capture, use the app, then return here — "
                "or click Re-analyze with the app running.")
            return
        if not is_probe_suitable_url(base):
            base = normalize_probe_url(base, self._app_name)
            self.base_url.setText(base)
            self.auto_hint.setText("Auto: switched to stable API root for probing")
        self.refresh()
        check = access_validator.check_base_url(base)
        parts = [ap.format_report(self._candidates), "", access_validator.format_base_check(check)]
        for c in self._candidates:
            if c.path_type in ("admin_endpoint", "credential"):
                access_validator.validate_candidate(c, base)
        if any(c.path_type in ("admin_endpoint", "credential") for c in self._candidates):
            parts[0] = ap.format_report(self._candidates)
        self.report.setPlainText("\n".join(parts))

    def _run_probe(self):
        from src.core import controlled_probe as cp
        from src.core.api_base_url import normalize_probe_url, is_probe_suitable_url
        base = self.base_url.text().strip()
        if not base:
            self._validate()
            return
        if not is_probe_suitable_url(base):
            base = normalize_probe_url(base, self._app_name)
            self.base_url.setText(base)
            self.auto_hint.setText("Auto: using stable API root for probe")
        tid = self.probe_template.currentData()
        result = cp.run_probe(tid, base)
        self._probe_results.append(result)
        try:
            from src.core import evidence_fusion
            from src.core.evidence_store import session_store
            evidence_fusion.ingest_probe_result(session_store(), result)
        except Exception:
            pass
        leaks = cp.analyze_leaks([result])
        block = cp.format_report([result], leaks)
        resp = result.get("response") or {}
        if result.get("skipped"):
            block += f"\n\nTip: {result.get('reason', '')}"
        elif resp.get("status") in (401, 403):
            block += "\n\n✓ Probe reached the API (auth required — expected)."
        elif resp.get("status", 0) >= 400:
            block += "\n\n✓ Server responded — probe is working."
        elif resp.get("error"):
            block += f"\n\n✗ Connection failed: {resp.get('error')}"
        self.report.append("\n\n" + block)
