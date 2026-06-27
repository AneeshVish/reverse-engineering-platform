
import sys
import os
import os
os.environ["PYTHONIOENCODING"] = "utf-8"
import logging
from pathlib import Path

# Add the src directory to the path
src_dir = Path(__file__).resolve().parent
sys.path.append(str(src_dir))

from src.gui.main_window import MainWindow
from src.utils.settings import Settings
from src.utils.logger import setup_logger
from src.plugins.plugin_manager import PluginManager
from PyQt6.QtWidgets import QApplication

def main():
    # Setup logging
    setup_logger()
    logger = logging.getLogger(__name__)
    logger.info("Starting Reverse Engineering Platform")

    # Load application settings
    settings = Settings()
    
    # Initialize the plugin manager
    plugin_manager = PluginManager(settings.get_plugin_directory())
    plugin_manager.load_plugins()
    
    # Create and start Qt application
    app = QApplication(sys.argv)
    app.setApplicationName("Reverse Engineering Platform")
    app.setOrganizationName("RE-Team")
    
    # Create main window
    window = MainWindow(settings, plugin_manager)
    window.show()
    
    # Start the event loop
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
