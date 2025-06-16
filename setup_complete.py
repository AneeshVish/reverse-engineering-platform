#!/usr/bin/env python3
"""Complete setup script for the Ultimate Reverse Engineering Platform"""

import subprocess
import sys
import os
from pathlib import Path

def install_requirements():
    """Install all required packages"""
    requirements = [
        "PyQt6>=6.0.0",
        "lief>=0.12.0", 
        "capstone>=5.0.0",
        "python-magic-bin>=0.4.14",
        "pyqtgraph>=0.13.0",
        "matplotlib>=3.5.0",
        "networkx>=2.8.0",
        "pandas>=1.5.0",
        "numpy>=1.21.0",
        "requests>=2.28.0"
    ]
    
    for req in requirements:
        print(f"Installing {req}...")
        subprocess.run([sys.executable, "-m", "pip", "install", req])

def create_directories():
    """Create necessary directories"""
    dirs = [
        "src/core",
        "src/gui", 
        "src/intelligence",
        "src/collaboration",
        "logs",
        "exports"
    ]
    
    for dir_path in dirs:
        Path(dir_path).mkdir(parents=True, exist_ok=True)
        # Create __init__.py files
        init_file = Path(dir_path) / "__init__.py"
        if not init_file.exists():
            init_file.touch()

def setup_config():
    """Create default configuration"""
    config = {
        "ai": {
            "model_type": "ollama",
            "api_key": ""
        },
        "misp": {
            "url": "",
            "api_key": ""
        },
        "visualization": {
            "entropy_window": 256,
            "cfg_layout": "spring"
        }
    }
    
    import json
    with open("config.json", "w") as f:
        json.dump(config, f, indent=2)

if __name__ == "__main__":
    print("Setting up Ultimate Reverse Engineering Platform...")
    
    create_directories()
    install_requirements()
    setup_config()
    
    print("\nSetup complete! You can now run:")
    print("python main.py")
