"""Headless smoke test: the GUI builds and both welcome modes work.

Runs under the Qt 'offscreen' platform so it works in CI without a display.
Skipped automatically if PyQt6 is not installed.
"""

import os
import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6")


@pytest.fixture(scope="module")
def app():
    from PyQt6.QtWidgets import QApplication
    instance = QApplication.instance() or QApplication([])
    yield instance


def _make_window(app):
    from src.utils.settings import Settings
    from src.plugins.plugin_manager import PluginManager
    from src.gui.main_window import MainWindow
    s = Settings()
    pm = PluginManager(s.get_plugin_directory())
    pm.load_plugins()
    return MainWindow(s, pm)


def test_cracking_mode_builds_full_ui(app):
    w = _make_window(app)
    w.launch_main_ui()
    assert w.analysis_tabs.count() >= 10
    assert "CAPABILITIES" in w.log_view.toPlainText()


def test_security_mode_focuses_audit_tab(app):
    w = _make_window(app)
    w.launch_security_mode()
    current = w.analysis_tabs.tabText(w.analysis_tabs.currentIndex())
    assert current == "Security Audit"
