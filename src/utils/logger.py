# -*- coding: utf-8 -*-

import logging
import sys
from pathlib import Path

def setup_logger(log_level=logging.INFO, log_file=None):
    '''Setup the application logger
    
    Args:
        log_level: The logging level
        log_file (str, optional): Path to log file
    '''
    # Create logs directory if it doesn't exist
    log_dir = Path('logs')
    log_dir.mkdir(exist_ok=True)
    
    # Default log file
    if log_file is None:
        log_file = log_dir / 'reverse_engineering_platform.log'
    
    # Configure logging
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    # Set specific logger levels
    logging.getLogger('PyQt6').setLevel(logging.WARNING)
    logging.getLogger('matplotlib').setLevel(logging.WARNING)
    
    logger = logging.getLogger(__name__)
    logger.info("Logger initialized")

class LogHandler(logging.Handler):
    '''Custom log handler for GUI'''
    
    def __init__(self, text_widget=None):
        super().__init__()
        self.text_widget = text_widget
    
    def emit(self, record):
        if self.text_widget:
            msg = self.format(record)
            self.text_widget.append(msg)
