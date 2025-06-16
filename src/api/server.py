from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import uvicorn
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from src.core.decompiler_manager import DecompilerManager, DecompilerEngine
from src.plugins.plugin_manager import PluginManager

app = FastAPI()

# Initialize core components
plugin_manager = PluginManager("plugins")
plugin_manager.load_plugins()
decompiler_manager = DecompilerManager()

@app.get("/status")
def status():
    return {"status": "ok"}

@app.post("/decompile")
async def decompile(request: Request):
    data = await request.json()
    assembly_code = data.get("assembly_code", "")
    engine = data.get("engine", "llm4decompile")
    results = decompiler_manager.decompile_parallel(assembly_code, engines=[DecompilerEngine.LLM4DECOMPILE])
    return results

@app.get("/plugins")
def list_plugins():
    return {"plugins": list(plugin_manager.plugins.keys())}

@app.post("/plugin/analyze")
async def plugin_analyze(request: Request):
    data = await request.json()
    plugin_name = data.get("plugin_name")
    binary_info = data.get("binary_info", {})
    plugin = plugin_manager.plugins.get(plugin_name)
    if not plugin:
        return JSONResponse(status_code=404, content={"error": "Plugin not found"})
    if hasattr(plugin, "analyze"):
        result = plugin.analyze(binary_info)
        return {"result": result}
    return JSONResponse(status_code=400, content={"error": "Plugin does not support analyze()"})

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
