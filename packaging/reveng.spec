# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec — builds a self-contained RevENG desktop app.

Usage (from repo root):
  pip install -r requirements.txt -r requirements-packaging.txt
  pyinstaller packaging/reveng.spec

Output:
  macOS  → dist/RevENG.app
  Linux  → dist/RevENG/RevENG
  Windows → dist/RevENG/RevENG.exe
"""

import sys
from pathlib import Path

block_cipher = None
# SPECPATH is the directory that holds this spec (…/packaging), so the repo
# root is exactly one level up.
ROOT = Path(SPECPATH).parent

datas = [
    (str(ROOT / "assets"), "assets"),
    (str(ROOT / "scripts"), "scripts"),
    (str(ROOT / "plugins"), "plugins"),
    (str(ROOT / "config.json"), "."),
]

hiddenimports = [
    "src",
    "PyQt6.sip",
    "PyQt6.QtCore",
    "PyQt6.QtGui",
    "PyQt6.QtWidgets",
    "PyQt6.QtWebEngineWidgets",
    "PyQt6.QtWebEngineCore",
    "PyQt6.QtWebChannel",
    "matplotlib.backends.backend_qtagg",
    "matplotlib.backends.backend_qt5agg",
    "capstone",
    "lief",
    "pefile",
    "Crypto",
    "Crypto.Cipher.AES",
    "numpy",
    "networkx",
    "pandas",
    "qtawesome",
    "requests",
    "openai",
    "pyqtgraph",
]

a = Analysis(
    [str(ROOT / "main.py")],
    pathex=[str(ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter"],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="RevENG",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="RevENG",
)

if sys.platform == "darwin":
    app = BUNDLE(
        coll,
        name="RevENG.app",
        icon=None,
        bundle_identifier="com.reveng.platform",
        info_plist={
            "CFBundleName": "RevENG",
            "CFBundleDisplayName": "RevENG",
            "CFBundleVersion": "1.0.0",
            "CFBundleShortVersionString": "1.0.0",
            "NSHighResolutionCapable": True,
        },
    )
