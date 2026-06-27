# -*- coding: utf-8 -*-

import logging
import importlib.util
import sys
from pathlib import Path


class PluginManager:
    def __init__(self, plugin_directory):
        self.logger = logging.getLogger(__name__)
        self.plugin_directory = Path(plugin_directory)
        self.plugins = {}
        self.hooks = {
            'on_load': [],
            'on_unload': [],
            'on_binary_load': [],
            'on_disassembly': [],
            'on_analysis': []
        }

    def load_plugins(self):
        '''Load all plugins from the plugin directory'''
        if not self.plugin_directory.exists():
            self.logger.warning(
                f"Plugin directory not found: "
                f"{self.plugin_directory}"
            )
            return

        self.logger.info(
            f"Loading plugins from "
            f"{self.plugin_directory}"
        )

        # Find all Python files in the plugin directory
        for plugin_file in self.plugin_directory.glob('*.py'):
            if plugin_file.name == '__init__.py':
                continue
            self.load_plugin(plugin_file)

    def load_plugin(self, plugin_file):
        '''Load a plugin from a file

        Args:
            plugin_file (Path): Path to the plugin file

        Returns:
            bool: True if the plugin was loaded successfully
        '''
        plugin_name = plugin_file.stem

        try:
            # Load the module
            spec = importlib.util.spec_from_file_location(
                plugin_name, plugin_file
            )
            module = importlib.util.module_from_spec(spec)
            sys.modules[plugin_name] = module
            spec.loader.exec_module(module)

            # Check if the module has a register_plugin function
            if not hasattr(module, 'register_plugin'):
                self.logger.warning(
                    f"Plugin {plugin_name} does not have a "
                    f"register_plugin function"
                )
                return False

            # Register the plugin
            plugin = module.register_plugin()
            if not plugin:
                self.logger.warning(
                    f"Plugin {plugin_name} "
                    f"registration failed"
                )
                return False

            # Store the plugin
            self.plugins[plugin_name] = plugin

            # Register hooks
            self._register_hooks(plugin)

            self.logger.info(f"Loaded plugin: {plugin_name}")
            return True

        except Exception as e:
            self.logger.error(
                f"Error loading plugin {plugin_name}: {e}"
            )
            return False

    def _register_hooks(self, plugin):
        '''Register plugin hooks

        Args:
            plugin: The plugin instance
        '''
        for hook_name in self.hooks.keys():
            if hasattr(plugin, hook_name):
                self.hooks[hook_name].append(plugin)
                self.logger.debug(
                    f"Registered hook {hook_name} for plugin "
                    f"{plugin.__class__.__name__}"
                )

    def unload_plugin(self, plugin_name):
        '''Unload a plugin

        Args:
            plugin_name (str): The name of the plugin to unload

        Returns:
            bool: True if the plugin was unloaded successfully
        '''
        if plugin_name not in self.plugins:
            self.logger.warning(
                f"Plugin not found: {plugin_name}"
            )
            return False

        plugin = self.plugins[plugin_name]

        # Remove hooks
        for hook_list in self.hooks.values():
            if plugin in hook_list:
                hook_list.remove(plugin)

        # Call on_unload if available
        if hasattr(plugin, 'on_unload'):
            try:
                plugin.on_unload()
            except Exception as e:
                self.logger.error(f"Error unloading plugin {plugin_name}: {e}")

        # Remove plugin
        del self.plugins[plugin_name]

        self.logger.info(
            f"Unloaded plugin: {plugin_name}"
        )
        return True

    def get_plugins(self):
        '''Get all loaded plugins

        Returns:
            dict: A dictionary of loaded plugins
        '''
        return self.plugins

    def execute_hook(self, hook_name, *args, **kwargs):
        '''Execute a hook

        Args:
            hook_name (str): The name of the hook to execute
            *args: Arguments to pass to the hook
            **kwargs: Keyword arguments to pass to the hook

        Returns:
            list: A list of results from the hook execution
        '''
        if hook_name not in self.hooks:
            self.logger.warning(f"Hook not found: {hook_name}")
            return []

        results = []
        for plugin in self.hooks[hook_name]:
            try:
                hook_method = getattr(plugin, hook_name)
                result = hook_method(*args, **kwargs)
                results.append(result)
            except Exception as e:
                self.logger.error(
                    f"Error executing hook {hook_name} for plugin "
                    f"{plugin.__class__.__name__}: {e}"
                )
        return results
