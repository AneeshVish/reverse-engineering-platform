"""Tests for the theming system."""

import os
import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6")

from src.gui import theme as th


@pytest.fixture(scope="module")
def app():
    from PyQt6.QtWidgets import QApplication
    return QApplication.instance() or QApplication([])


def test_three_themes_registered():
    assert set(th.THEMES) == {"Tokyo Night", "Cyber Neon", "Enterprise Slate"}
    assert th.DEFAULT_THEME in th.THEMES


@pytest.mark.parametrize("name", list(th.THEMES))
def test_build_qss_nonempty_and_substitutes(app, name):
    qss = th.build_qss(th.THEMES[name])
    assert len(qss) > 1000
    assert "{t." not in qss and "{ui}" not in qss and "{mono}" not in qss  # substituted
    assert th.THEMES[name].accent in qss


@pytest.mark.parametrize("name", list(th.THEMES))
def test_apply_theme_sets_stylesheet(app, name):
    applied = th.apply_theme(app, name)
    assert applied.name == name
    assert app.styleSheet()


def test_apply_unknown_theme_falls_back(app):
    applied = th.apply_theme(app, "Nope")
    assert applied.name == th.DEFAULT_THEME


def test_resolve_fonts_returns_two_families(app):
    th.load_bundled_fonts(app)
    ui, mono = th.resolve_fonts()
    assert isinstance(ui, str) and ui
    assert isinstance(mono, str) and mono
