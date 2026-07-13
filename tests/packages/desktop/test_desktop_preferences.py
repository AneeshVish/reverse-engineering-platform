"""Desktop-sdk tests: Preferences defaults and JSON persistence."""

from __future__ import annotations

from pathlib import Path

from reveng_desktop_sdk.preferences import Preferences, PreferencesStore


def test_defaults() -> None:
    prefs = Preferences()
    assert prefs.theme == "dark"
    assert prefs.autosave is True
    assert prefs.recent_project_limit == 10
    assert prefs.api_base_url == "http://127.0.0.1:8000"


def test_store_returns_defaults_when_missing(tmp_path: Path) -> None:
    store = PreferencesStore(tmp_path / "preferences.json")
    assert store.load() == Preferences()


def test_round_trip(tmp_path: Path) -> None:
    store = PreferencesStore(tmp_path / "preferences.json")
    prefs = Preferences(theme="light", recent_project_limit=5)
    store.save(prefs)

    loaded = store.load()
    assert loaded == prefs


def test_round_trip_preserves_window_state(tmp_path: Path) -> None:
    store = PreferencesStore(tmp_path / "preferences.json")
    prefs = Preferences(window_state={"width": 1200, "height": 800})
    store.save(prefs)

    loaded = store.load()
    assert loaded.window_state == {"width": 1200, "height": 800}
