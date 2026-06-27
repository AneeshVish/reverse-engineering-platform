"""Centralized theming for the whole app.

Replaces the old hardcoded inline stylesheets. Defines three themes as token sets,
generates one comprehensive QSS from those tokens, and applies a matching QPalette.
Fonts resolve to bundled families (JetBrains Mono / Inter) when loaded, else to
sensible per-platform fallbacks so nothing ever looks broken.
"""

import os
import sys
from dataclasses import dataclass

from PyQt6.QtGui import QColor, QFontDatabase, QPalette

ASSETS_FONTS = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "assets", "fonts",
)

# Families we ship; resolve_fonts() confirms which actually loaded.
_BUNDLED = {
    "mono": ("JetBrains Mono", ["JetBrainsMono-Regular.ttf", "JetBrainsMono-Bold.ttf"]),
    "ui": ("Inter", ["Inter-Variable.ttf", "Inter-Regular.ttf"]),
}
_loaded_families = set()


def load_bundled_fonts(app=None):
    """Register bundled .ttf files with Qt. Call once at startup (needs a QApp)."""
    for fname in os.listdir(ASSETS_FONTS) if os.path.isdir(ASSETS_FONTS) else []:
        if fname.lower().endswith((".ttf", ".otf")):
            fid = QFontDatabase.addApplicationFont(os.path.join(ASSETS_FONTS, fname))
            for fam in QFontDatabase.applicationFontFamilies(fid):
                _loaded_families.add(fam)


def _family(kind):
    fam = _BUNDLED[kind][0]
    if any(fam.lower() in f.lower() for f in _loaded_families):
        return fam
    if kind == "mono":
        if sys.platform == "darwin":
            return "Menlo"
        if sys.platform.startswith("win"):
            return "Consolas"
        return "DejaVu Sans Mono"
    # ui
    if sys.platform == "darwin":
        return ".AppleSystemUIFont"
    if sys.platform.startswith("win"):
        return "Segoe UI"
    return "DejaVu Sans"


def resolve_fonts():
    """Return (ui_family, mono_family) resolving bundled -> platform fallback."""
    return _family("ui"), _family("mono")


@dataclass(frozen=True)
class Theme:
    name: str
    bg: str
    bg_alt: str
    panel: str
    panel_alt: str
    border: str
    text: str
    text_dim: str
    accent: str
    accent_hover: str
    ok: str
    warn: str
    error: str
    selection: str


TOKYO_NIGHT = Theme(
    name="Tokyo Night",
    bg="#1a1b26", bg_alt="#16161e", panel="#24283b", panel_alt="#2f334d",
    border="#3b4261", text="#c0caf5", text_dim="#7f8bb0",
    accent="#7aa2f7", accent_hover="#9eb8ff", ok="#9ece6a", warn="#e0af68",
    error="#f7768e", selection="#364a82",
)

CYBER_NEON = Theme(
    name="Cyber Neon",
    bg="#0a0e14", bg_alt="#05080d", panel="#0d1117", panel_alt="#11181f",
    border="#1f6f6a", text="#c9d1d9", text_dim="#5b6b6a",
    accent="#00ffd1", accent_hover="#5cffe4", ok="#39ff14", warn="#ffcb6b",
    error="#ff2e88", selection="#0c3b38",
)

ENTERPRISE_SLATE = Theme(
    name="Enterprise Slate",
    bg="#0f172a", bg_alt="#0b1120", panel="#1e293b", panel_alt="#273449",
    border="#334155", text="#e2e8f0", text_dim="#94a3b8",
    accent="#3b82f6", accent_hover="#60a5fa", ok="#22c55e", warn="#f59e0b",
    error="#ef4444", selection="#1e40af",
)

THEMES = {t.name: t for t in (TOKYO_NIGHT, CYBER_NEON, ENTERPRISE_SLATE)}
DEFAULT_THEME = TOKYO_NIGHT.name


def build_qss(theme: Theme) -> str:
    ui, mono = resolve_fonts()
    t = theme
    return f"""
* {{
    font-family: "{ui}", "Segoe UI", "Helvetica Neue", sans-serif;
    font-size: 14px;
    outline: none;
}}
QMainWindow, QDialog {{ background: {t.bg}; }}
QWidget {{ background: {t.bg}; color: {t.text}; }}
QFrame#ActivityRail {{ background: {t.bg_alt}; border-right: 1px solid {t.border}; }}
QToolButton#RailButton {{
    background: transparent; border: none; border-radius: 10px;
    padding: 10px; margin: 4px 6px; color: {t.text_dim};
}}
QToolButton#RailButton:hover {{ background: {t.panel}; color: {t.text}; }}
QToolButton#RailButton:checked {{ background: {t.panel_alt}; color: {t.accent};
    border-left: 2px solid {t.accent}; }}

QToolBar {{ background: {t.bg_alt}; border: none; spacing: 8px; padding: 9px 14px; }}
QToolBar#MainToolBar {{ border-bottom: 1px solid {t.border}; }}
QToolBar QToolButton {{ background: transparent; color: {t.text}; padding: 8px 12px;
    border-radius: 8px; }}
QToolBar QToolButton:hover {{ background: {t.panel}; color: {t.accent}; }}

QToolBar#ActivityRail {{ background: {t.bg_alt}; border-right: 1px solid {t.border};
    padding: 10px 6px; spacing: 6px; }}
QToolBar#ActivityRail QToolButton {{ background: transparent; border: none;
    border-radius: 10px; padding: 11px; margin: 3px 5px; color: {t.text_dim}; }}
QToolBar#ActivityRail QToolButton:hover {{ background: {t.panel}; color: {t.text}; }}
QToolBar#ActivityRail QToolButton:checked {{ background: {t.panel_alt}; color: {t.accent}; }}

QLabel {{ background: transparent; color: {t.text}; }}
QLabel#Heading {{ font-size: 16px; font-weight: 600; color: {t.text};
    padding: 2px 0; }}
QLabel#Brand {{ font-size: 18px; font-weight: 700; color: {t.accent}; }}
QLabel#Dim {{ color: {t.text_dim}; padding: 3px 0; }}

QTabWidget::pane {{ border: 1px solid {t.border}; border-radius: 10px;
    background: {t.panel}; top: -1px; }}
QTabBar {{ qproperty-drawBase: 0; background: transparent; }}
QTabBar::tab {{ background: transparent; color: {t.text_dim};
    padding: 11px 20px; margin-right: 3px; border: none;
    border-bottom: 2px solid transparent; }}
QTabBar::tab:hover {{ color: {t.text}; }}
QTabBar::tab:selected {{ color: {t.accent}; border-bottom: 2px solid {t.accent}; }}
QTabBar::close-button {{ subcontrol-position: right; }}

QPushButton {{ background: {t.panel_alt}; color: {t.text};
    border: 1px solid {t.border}; border-radius: 9px; padding: 10px 18px;
    min-height: 18px; }}
QPushButton:hover {{ background: {t.panel}; border-color: {t.accent}; color: {t.accent}; }}
QPushButton:pressed {{ background: {t.selection}; }}
QPushButton:disabled {{ color: {t.text_dim}; border-color: {t.border}; background: {t.bg_alt}; }}
QPushButton#Primary {{ background: {t.accent}; color: {t.bg}; border: none;
    font-weight: 600; padding: 12px 18px; }}
QPushButton#Primary:hover {{ background: {t.accent_hover}; }}

QLineEdit, QComboBox, QSpinBox {{ background: {t.bg_alt}; color: {t.text};
    border: 1px solid {t.border}; border-radius: 8px; padding: 9px 12px;
    min-height: 18px; selection-background-color: {t.selection}; }}
QLineEdit:focus, QComboBox:focus {{ border: 1px solid {t.accent}; }}
QComboBox::drop-down {{ border: none; width: 24px; }}
QComboBox QAbstractItemView {{ background: {t.panel}; color: {t.text};
    border: 1px solid {t.border}; selection-background-color: {t.selection};
    border-radius: 8px; padding: 5px; }}

QTextEdit, QPlainTextEdit {{ background: {t.bg_alt}; color: {t.text};
    border: 1px solid {t.border}; border-radius: 10px; padding: 14px;
    font-family: "{mono}", monospace; font-size: 14px;
    selection-background-color: {t.selection}; }}

QTreeWidget, QTreeView, QTableWidget, QTableView, QListWidget {{
    background: {t.bg_alt}; color: {t.text}; border: 1px solid {t.border};
    border-radius: 10px; alternate-background-color: {t.panel};
    selection-background-color: {t.selection}; selection-color: {t.text};
    gridline-color: {t.border}; }}
QTreeWidget::item, QListWidget::item, QTableWidget::item {{ padding: 8px 8px; }}
QTreeWidget::item:selected, QListWidget::item:selected {{ background: {t.selection}; }}
QHeaderView::section {{ background: {t.panel}; color: {t.text_dim};
    padding: 10px 10px; border: none; border-bottom: 1px solid {t.border};
    font-size: 12px; }}

QDockWidget {{ color: {t.text}; titlebar-close-icon: none; titlebar-normal-icon: none; }}
QDockWidget::title {{ background: {t.panel}; color: {t.text_dim};
    padding: 10px 14px; border-bottom: 1px solid {t.border};
    text-transform: uppercase; font-size: 12px; letter-spacing: 1px; }}

QSplitter::handle {{ background: {t.border}; }}
QSplitter::handle:horizontal {{ width: 1px; }}
QSplitter::handle:vertical {{ height: 1px; }}

QMenuBar {{ background: {t.bg_alt}; color: {t.text}; border-bottom: 1px solid {t.border}; }}
QMenuBar::item {{ background: transparent; padding: 8px 14px; }}
QMenuBar::item:selected {{ background: {t.panel}; border-radius: 6px; }}
QMenu {{ background: {t.panel}; color: {t.text}; border: 1px solid {t.border};
    border-radius: 8px; padding: 6px; }}
QMenu::item {{ padding: 8px 24px; border-radius: 6px; }}
QMenu::item:selected {{ background: {t.selection}; color: {t.accent}; }}

QStatusBar {{ background: {t.bg_alt}; color: {t.text_dim};
    border-top: 1px solid {t.border}; min-height: 26px; }}
QStatusBar QLabel {{ color: {t.text_dim}; padding: 3px 10px; }}

QProgressBar {{ background: {t.bg_alt}; border: 1px solid {t.border};
    border-radius: 8px; text-align: center; color: {t.text}; height: 16px; }}
QProgressBar::chunk {{ background: {t.accent}; border-radius: 7px; }}

QCheckBox {{ background: transparent; color: {t.text}; spacing: 8px; }}
QCheckBox::indicator {{ width: 16px; height: 16px; border-radius: 5px;
    border: 1px solid {t.border}; background: {t.bg_alt}; }}
QCheckBox::indicator:checked {{ background: {t.accent}; border-color: {t.accent}; }}

QScrollBar:vertical {{ background: transparent; width: 12px; margin: 2px; }}
QScrollBar::handle:vertical {{ background: {t.border}; min-height: 28px; border-radius: 6px; }}
QScrollBar::handle:vertical:hover {{ background: {t.accent}; }}
QScrollBar:horizontal {{ background: transparent; height: 12px; margin: 2px; }}
QScrollBar::handle:horizontal {{ background: {t.border}; min-width: 28px; border-radius: 6px; }}
QScrollBar::handle:horizontal:hover {{ background: {t.accent}; }}
QScrollBar::add-line, QScrollBar::sub-line {{ width: 0; height: 0; }}
QScrollBar::add-page, QScrollBar::sub-page {{ background: transparent; }}

QToolTip {{ background: {t.panel}; color: {t.text}; border: 1px solid {t.accent};
    border-radius: 6px; padding: 5px 8px; }}

QFrame#Card {{ background: {t.panel}; border: 1px solid {t.border}; border-radius: 12px; }}
"""


def apply_theme(app, name=None):
    """Apply a theme to the QApplication: bundled fonts + QPalette + QSS."""
    theme = THEMES.get(name) or THEMES[DEFAULT_THEME]
    pal = QPalette()
    pal.setColor(QPalette.ColorRole.Window, QColor(theme.bg))
    pal.setColor(QPalette.ColorRole.Base, QColor(theme.bg_alt))
    pal.setColor(QPalette.ColorRole.AlternateBase, QColor(theme.panel))
    pal.setColor(QPalette.ColorRole.Text, QColor(theme.text))
    pal.setColor(QPalette.ColorRole.WindowText, QColor(theme.text))
    pal.setColor(QPalette.ColorRole.Button, QColor(theme.panel_alt))
    pal.setColor(QPalette.ColorRole.ButtonText, QColor(theme.text))
    pal.setColor(QPalette.ColorRole.Highlight, QColor(theme.selection))
    pal.setColor(QPalette.ColorRole.HighlightedText, QColor(theme.text))
    pal.setColor(QPalette.ColorRole.ToolTipBase, QColor(theme.panel))
    pal.setColor(QPalette.ColorRole.ToolTipText, QColor(theme.text))
    pal.setColor(QPalette.ColorRole.PlaceholderText, QColor(theme.text_dim))
    app.setPalette(pal)
    app.setStyleSheet(build_qss(theme))
    return theme
