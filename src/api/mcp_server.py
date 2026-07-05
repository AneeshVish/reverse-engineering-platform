"""MCP-compatible analysis server — exposes ProgramModel, capture, MCGD tools."""

import json
import os
import sys
from typing import Any, Dict, Optional

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import uvicorn

app = FastAPI(title="RevENG MCP Analysis Server")

_session: Dict[str, Any] = {
    "program_model": None,
    "capture_events": [],
    "decompile_status": {},
}


def set_program_model(model):
    _session["program_model"] = model


def add_capture_event(event_dict: dict):
    _session["capture_events"].append(event_dict)
    if len(_session["capture_events"]) > 1000:
        _session["capture_events"] = _session["capture_events"][-500:]


@app.get("/mcp/tools")
def list_tools():
    return {
        "tools": [
            {"name": "list_functions", "description": "List discovered functions"},
            {"name": "get_program_stats", "description": "Instruction/block counts"},
            {"name": "list_capture_events", "description": "Recent PlaintextEvents"},
            {"name": "run_mcgd", "description": "Run MCGD on C source snippet"},
        ]
    }


@app.post("/mcp/call")
async def call_tool(request: Request):
    data = await request.json()
    tool = data.get("tool")
    args = data.get("arguments", {})
    model = _session.get("program_model")

    if tool == "list_functions":
        funcs = []
        if model and hasattr(model, "instructions"):
            for block in model.basic_blocks()[:100]:
                funcs.append({"address": hex(block.start), "size": len(block.instructions)})
        return {"functions": funcs}

    if tool == "get_program_stats":
        if model:
            return model.stats()
        return {"instructions": 0}

    if tool == "list_capture_events":
        limit = int(args.get("limit", 50))
        return {"events": _session["capture_events"][-limit:]}

    if tool == "run_mcgd":
        from src.core.mcgd.orchestrator import MCGDOrchestrator
        code = args.get("code", "")
        binary = args.get("binary", "")
        orch = MCGDOrchestrator(original_binary=binary)
        result = orch.run(code)
        return {
            "verified": result.verified,
            "reward": result.final_reward,
            "code": result.code,
            "iterations": len(result.iterations),
        }

    return JSONResponse(status_code=400, content={"error": f"Unknown tool: {tool}"})


@app.get("/status")
def status():
    return {"status": "ok", "mcp": True}


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8765)
