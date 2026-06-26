"""Headless construction + handler smoke tests for every GUI panel.

These encode the exhaustive harness used during hardening: every panel must
construct, the analysis pipeline must build a program model from a real binary,
and the MainWindow handlers must run without crashing (dialogs are stubbed).
"""

import os
import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6")


@pytest.fixture(scope="module")
def app():
    from PyQt6.QtWidgets import QApplication
    return QApplication.instance() or QApplication([])


@pytest.fixture(autouse=True)
def no_modal_dialogs(monkeypatch, tmp_path):
    """Neutralize modal dialogs so handlers never block in a headless run."""
    from PyQt6.QtWidgets import QFileDialog, QInputDialog, QMessageBox
    sample = tmp_path / "in.bin"
    sample.write_bytes(b"hello world")
    out = str(tmp_path / "out.txt")
    monkeypatch.setattr(QFileDialog, "getOpenFileName", staticmethod(lambda *a, **k: (str(sample), "")))
    monkeypatch.setattr(QFileDialog, "getSaveFileName", staticmethod(lambda *a, **k: (out, "")))
    monkeypatch.setattr(QFileDialog, "getExistingDirectory", staticmethod(lambda *a, **k: str(tmp_path)))
    monkeypatch.setattr(QInputDialog, "getText", staticmethod(lambda *a, **k: ("q", True)))
    monkeypatch.setattr(QMessageBox, "information", staticmethod(lambda *a, **k: None))
    monkeypatch.setattr(QMessageBox, "warning", staticmethod(lambda *a, **k: None))
    monkeypatch.setattr(QMessageBox, "critical", staticmethod(lambda *a, **k: None))


PANEL_IMPORTS = [
    ("src.gui.crypto_tools_panel", "CryptoToolsPanel"),
    ("src.gui.key_analysis_panel", "KeyAnalysisPanel"),
    ("src.gui.security_audit_panel", "SecurityAuditPanel"),
    ("src.gui.network_capture_panel", "NetworkCapturePanel"),
    ("src.gui.advanced_viewer", "AdvancedVisualizationWidget"),
    ("src.gui.advanced_viewer", "AIAnalysisPanel"),
    ("src.gui.advanced_viewer", "MemoryMapWidget"),
    ("src.gui.views", "DisassemblyView"),
    ("src.gui.views", "BinaryInfoView"),
    ("src.gui.unified_viewer", "UnifiedViewer"),
    ("src.gui.pseudocode_toggle_widget", "PseudocodeToggleWidget"),
]


@pytest.mark.parametrize("module,cls", PANEL_IMPORTS)
def test_panel_constructs(app, module, cls):
    import importlib
    klass = getattr(importlib.import_module(module), cls)
    widget = klass()
    assert widget is not None


def test_entropy_plot_handles_bytes(app):
    """Regression: set_binary_data used to crash on bytes via np.bincount."""
    from src.gui.advanced_viewer import AdvancedVisualizationWidget
    w = AdvancedVisualizationWidget()
    w.set_binary_data(bytes(range(256)) * 16)  # 4 KB


def test_cfg_viewer_builds(app):
    from src.gui.cfg_viewer import CFGViewer
    ins = [
        {"address": 0, "mnemonic": "cmp", "op_str": "eax, 0", "size": 2},
        {"address": 2, "mnemonic": "je", "op_str": "0x6", "size": 2},
        {"address": 4, "mnemonic": "nop", "op_str": "", "size": 1},
        {"address": 6, "mnemonic": "ret", "op_str": "", "size": 1},
    ]
    CFGViewer(ins)


@pytest.fixture(scope="module")
def main_window(app):
    from src.utils.settings import Settings
    from src.plugins.plugin_manager import PluginManager
    from src.gui.main_window import MainWindow
    s = Settings()
    pm = PluginManager(s.get_plugin_directory())
    pm.load_plugins()
    w = MainWindow(s, pm)
    w.launch_main_ui()
    return w


@pytest.mark.skipif(not os.path.exists("/bin/ls"), reason="no sample binary")
def test_full_pipeline_builds_model(main_window):
    from src.core.universal_loader import UniversalLoader
    from src.core.disassembler import DisassemblerEngine
    from src.gui.main_window import BinaryAnalysisWorker
    w = main_window
    w.current_file_path = "/bin/ls"
    worker = BinaryAnalysisWorker(UniversalLoader(), DisassemblerEngine(), "/bin/ls")
    captured = {}
    worker.analysis_complete.connect(lambda r: captured.update(r))
    worker.run()
    assert "instructions" in captured
    w.ai_decompile_cb.setChecked(False)   # don't spawn the AI worker
    w.on_analysis_complete(captured)
    assert w.program_model is not None


def test_handlers_do_not_crash(main_window):
    w = main_window
    for name in ("export_iocs", "export_analysis", "configure_misp",
                 "download_log_file", "download_disassembly", "show_cfg_viewer",
                 "run_full_decompilation"):
        getattr(w, name)()


def test_ai_handlers_gate_without_ollama(main_window, monkeypatch):
    """AI handlers must no-op cleanly (not block/crash) when Ollama is absent."""
    from src.core import capabilities
    monkeypatch.setattr(capabilities, "tool_available", lambda key: False)
    w = main_window
    w.source_code_view.setPlainText("int main(){return 0;}")
    w.ask_ai_about_code()
    w.summarize_function_with_ai()
    w.enhance_with_ai_comments()
