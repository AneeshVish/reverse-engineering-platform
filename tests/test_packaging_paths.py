"""Packaging path helpers."""

from src.utils.paths import asset_path, bundle_root, is_frozen, project_root, script_path, user_data_dir


def test_dev_bundle_root_is_repo():
    assert not is_frozen()
    root = bundle_root()
    assert (root / "main.py").is_file()
    assert (root / "assets" / "web" / "cfg_render.html").is_file()


def test_asset_path():
    html = asset_path("web", "cfg_render.html")
    assert html.endswith("cfg_render.html")


def test_script_path_resolves():
    p = script_path("find_key_strings")
    assert p.endswith("find_key_strings.py")


def test_user_data_dir_exists(tmp_path, monkeypatch):
    monkeypatch.setenv("REVENG_DATA_DIR", str(tmp_path / "reveng-data"))
    d = user_data_dir()
    assert d.is_dir()


def test_project_root_alias():
    assert project_root() == str(bundle_root())
