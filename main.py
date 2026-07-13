
import sys
import os
os.environ["PYTHONIOENCODING"] = "utf-8"
import logging
from pathlib import Path

# Dev mode: add src to path. Frozen builds bundle everything via PyInstaller.
if not getattr(sys, "frozen", False):
    src_dir = Path(__file__).resolve().parent
    sys.path.append(str(src_dir))

from src.gui.main_window import MainWindow
from src.utils.settings import Settings
from src.utils.logger import setup_logger
from src.utils.paths import _ensure_user_layout
from src.plugins.plugin_manager import PluginManager
from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import Qt

def main():
    # Setup logging
    setup_logger()
    logger = logging.getLogger(__name__)
    logger.info("Starting Reverse Engineering Platform")

    if getattr(sys, "frozen", False):
        _ensure_user_layout()

    # Load application settings
    settings = Settings()
    
    # Initialize the plugin manager
    plugin_manager = PluginManager(settings.get_plugin_directory())
    plugin_manager.load_plugins()
    
    # WebEngine requires shared GL contexts — skip in headless CI (offscreen).
    import os
    if os.environ.get("QT_QPA_PLATFORM", "").lower() != "offscreen":
        QApplication.setAttribute(Qt.ApplicationAttribute.AA_ShareOpenGLContexts, True)
    app = QApplication(sys.argv)
    app.setApplicationName("RevENG")
    app.setOrganizationName("RE-Team")

    # Modern theming: load bundled fonts, then apply the saved theme globally
    # BEFORE building the window so the welcome screen is themed too.
    from src.gui import theme as theme_mod
    theme_mod.load_bundled_fonts(app)
    theme_mod.apply_theme(app, settings.get_theme())

    # Phase 016: construct the desktop-SDK manager once, up front, and hand
    # it to MainWindow. Fully optional -- if the SDK isn't importable for
    # any reason, the legacy app still launches unchanged (10.12).
    desktop_manager = None
    try:
        from reveng_desktop_sdk import build_desktop_manager
        desktop_manager = build_desktop_manager()
    except Exception as e:
        logger.warning("Pipeline Workspace unavailable (desktop SDK): %s", e)

    # Create main window
    window = MainWindow(settings, plugin_manager, desktop_manager=desktop_manager)
    window.show()
    
    # Start the event loop
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
