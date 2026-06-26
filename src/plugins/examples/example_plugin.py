# Example plugin moved for industry-level structure
from src.plugins.base_plugin import BasePlugin


class ExamplePlugin(BasePlugin):
    def __init__(self):
        super().__init__()
        self.name = "ExamplePlugin"
        self.description = "A sample plugin for demonstration purposes."
        self.version = "0.1.0"
        self.author = "Your Name"

    def on_load(self):
        print(f"[PLUGIN] {self.name} loaded.")

    def on_unload(self):
        print(f"[PLUGIN] {self.name} unloaded.")

    def on_binary_load(self, binary_info):
        print(f"[PLUGIN] {self.name} binary loaded: {binary_info}")
