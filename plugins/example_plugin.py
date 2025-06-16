from src.plugins.base_plugin import BasePlugin

class ExamplePlugin(BasePlugin):
    def __init__(self):
        super().__init__()
        self.name = "ExamplePlugin"
        self.description = "A sample plugin that prints a greeting."
        self.version = "1.0.0"
        self.author = "Cascade AI"

    def on_load(self):
        print(f"[PLUGIN] {self.name} loaded!")

    def analyze(self, binary_info):
        print(f"[PLUGIN] Analyzing binary: {binary_info}")
        # Return a dummy analysis result
        return {"result": "Hello from ExamplePlugin!"}

def register_plugin():
    return ExamplePlugin()
