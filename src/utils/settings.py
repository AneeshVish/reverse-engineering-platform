# -*- coding: utf-8 -*-

import json
import logging
from pathlib import Path

class Settings:
    '''Application settings manager'''
    
    def __init__(self, config_file='config.json'):
        self.logger = logging.getLogger(__name__)
        self.config_file = Path(config_file)
        self.settings = self._load_default_settings()
        self.load()
    
    def _load_default_settings(self):
        '''Load default settings'''
        return {
            'general': {
                'theme': 'dark',
                'font_family': 'Consolas',
                'font_size': 9,
                'auto_save': True
            },
            'directories': {
                'plugin_dir': 'plugins',
                'project_dir': 'projects',
                'temp_dir': 'temp'
            },
            'disassembly': {
                'show_bytes': True,
                'show_addresses': True,
                'syntax_highlighting': True,
                'auto_analyze': True
            },
            'debugger': {
                'auto_attach': False,
                'default_timeout': 30,
                'log_api_calls': True
            },
            'ai': {
                'enabled': False,
                'api_key': '',
                'model': 'gpt-3.5-turbo',
                'max_tokens': 1000
            }
        }
    
    def load(self):
        '''Load settings from file'''
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    loaded_settings = json.load(f)
                    self._merge_settings(loaded_settings)
                self.logger.info(f"Settings loaded from {self.config_file}")
            except Exception as e:
                self.logger.error(f"Error loading settings: {e}")
    
    def save(self):
        '''Save settings to file'''
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.settings, f, indent=2)
            self.logger.info(f"Settings saved to {self.config_file}")
            return True
        except Exception as e:
            self.logger.error(f"Error saving settings: {e}")
            return False
    
    def _merge_settings(self, loaded_settings):
        '''Merge loaded settings with defaults'''
        for category, values in loaded_settings.items():
            if category in self.settings:
                self.settings[category].update(values)
            else:
                self.settings[category] = values
    
    def get(self, category, key=None, default=None):
        '''Get a setting value'''
        if category not in self.settings:
            return default
        
        if key is None:
            return self.settings[category]
        
        return self.settings[category].get(key, default)
    
    def set(self, category, key, value):
        '''Set a setting value'''
        if category not in self.settings:
            self.settings[category] = {}
        
        self.settings[category][key] = value
    
    def get_plugin_directory(self):
        '''Get the plugin directory'''
        return self.get('directories', 'plugin_dir', 'plugins')
    
    def get_project_directory(self):
        '''Get the project directory'''
        return self.get('directories', 'project_dir', 'projects')
    
    def get_temp_directory(self):
        '''Get the temporary directory'''
        return self.get('directories', 'temp_dir', 'temp')
