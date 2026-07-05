# -*- coding: utf-8 -*-

import json
import logging
from pathlib import Path

from src.utils.paths import _ensure_user_layout, bundle_root, is_frozen, user_data_dir


def default_config_path() -> Path:
    if is_frozen():
        _ensure_user_layout()
        return user_data_dir() / "config.json"
    root_cfg = bundle_root() / "config.json"
    if root_cfg.is_file():
        return root_cfg
    return Path("config.json")


def _resolve_directory(relative: str) -> str:
    p = Path(relative)
    if p.is_absolute():
        p.mkdir(parents=True, exist_ok=True)
        return str(p)
    base = user_data_dir() if is_frozen() else bundle_root()
    resolved = base / p
    resolved.mkdir(parents=True, exist_ok=True)
    return str(resolved)


class Settings:
    """Application settings manager."""

    def __init__(self, config_file=None):
        self.logger = logging.getLogger(__name__)
        self.config_file = Path(config_file) if config_file else default_config_path()
        self.settings = self._load_default_settings()
        self.load()

    def _load_default_settings(self):
        return {
            "general": {
                "theme": "dark",
                "font_family": "Consolas",
                "font_size": 9,
                "auto_save": True,
            },
            "directories": {
                "plugin_dir": "plugins",
                "project_dir": "projects",
                "temp_dir": "temp",
            },
            "disassembly": {
                "show_bytes": True,
                "show_addresses": True,
                "syntax_highlighting": True,
                "auto_analyze": True,
            },
            "debugger": {
                "auto_attach": False,
                "default_timeout": 30,
                "log_api_calls": True,
            },
            "ai": {
                "enabled": False,
                "api_key": "",
                "model": "gpt-3.5-turbo",
                "max_tokens": 1000,
            },
        }

    def load(self):
        if self.config_file.exists():
            try:
                with open(self.config_file, "r", encoding="utf-8") as f:
                    loaded_settings = json.load(f)
                    self._merge_settings(loaded_settings)
                self.logger.info("Settings loaded from %s", self.config_file)
            except Exception as e:
                self.logger.error("Error loading settings: %s", e)

    def save(self):
        try:
            self.config_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.config_file, "w", encoding="utf-8") as f:
                json.dump(self.settings, f, indent=2)
            self.logger.info("Settings saved to %s", self.config_file)
            return True
        except Exception as e:
            self.logger.error("Error saving settings: %s", e)
            return False

    def _merge_settings(self, loaded_settings):
        for category, values in loaded_settings.items():
            if category in self.settings:
                self.settings[category].update(values)
            else:
                self.settings[category] = values

    def get(self, category, key=None, default=None):
        if category not in self.settings:
            return default
        if key is None:
            return self.settings[category]
        return self.settings[category].get(key, default)

    def set(self, category, key, value):
        if category not in self.settings:
            self.settings[category] = {}
        self.settings[category][key] = value

    def get_theme(self):
        return self.get("general", "theme", "Tokyo Night")

    def set_theme(self, name):
        self.set("general", "theme", name)
        self.save()

    def get_plugin_directory(self):
        return _resolve_directory(self.get("directories", "plugin_dir", "plugins"))

    def get_project_directory(self):
        return _resolve_directory(self.get("directories", "project_dir", "projects"))

    def get_temp_directory(self):
        return _resolve_directory(self.get("directories", "temp_dir", "temp"))
