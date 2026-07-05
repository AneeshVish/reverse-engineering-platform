"""Interactive 3D CFG viewer via QWebEngineView + Three.js + QWebChannel."""

import json
import os

from PyQt6.QtCore import QObject, QUrl, pyqtSlot
from PyQt6.QtWidgets import QVBoxLayout, QWidget

from src.utils.paths import project_root

try:
    from PyQt6.QtWebEngineWidgets import QWebEngineView
    from PyQt6.QtWebChannel import QWebChannel
    from PyQt6.QtWebEngineCore import QWebEngineSettings
    WEBENGINE = True
except ImportError:
    WEBENGINE = False
    QWebEngineView = QWidget  # type: ignore
    QWebEngineSettings = None  # type: ignore


def _block_payload(addr, block) -> dict:
    """Rich node attributes for 3D tooltips."""
    instr_lines = []
    for ins in block.instructions:
        line = f"{ins.get('mnemonic', '')} {ins.get('op_str', '')}".strip()
        if ins.get("comment"):
            line += f"  ; {ins['comment']}"
        instr_lines.append(line)
    comment = block.instructions[0].get("comment", "") if block.instructions else ""
    return {
        "label": block.label(),
        "address": f"0x{addr:x}",
        "address_int": addr,
        "instruction_count": len(block.instructions),
        "disassembly": "\n".join(instr_lines),
        "successors": [f"0x{s:x}" for s in block.successors],
        "comment": comment,
    }


class GraphBridge(QObject):
    def __init__(self, program_model):
        super().__init__()
        self.program_model = program_model

    @pyqtSlot(result=str)
    def get_graph_data(self):
        model = self.program_model
        nodes = []
        blocks = model.blocks if hasattr(model, "blocks") else {}
        if not blocks and hasattr(model, "basic_blocks"):
            blocks = {b.start: b for b in model.basic_blocks()}
        for addr, block in blocks.items():
            nodes.append({
                "key": str(addr),
                "attributes": _block_payload(addr, block),
            })
        edges = [{"source": str(u), "target": str(v)} for u, v in (model.cfg_edges or [])]
        if not edges and blocks:
            for addr, block in blocks.items():
                for succ in block.successors:
                    edges.append({"source": str(addr), "target": str(succ)})
        return json.dumps({"nodes": nodes, "edges": edges})

    @pyqtSlot(str, result=str)
    def get_node_detail(self, key: str) -> str:
        """Return JSON detail for a single block (click handler fallback)."""
        model = self.program_model
        try:
            addr = int(key)
        except ValueError:
            return "{}"
        blocks = model.blocks if hasattr(model, "blocks") else {}
        block = blocks.get(addr)
        if not block and hasattr(model, "basic_blocks"):
            for b in model.basic_blocks():
                if b.start == addr:
                    block = b
                    break
        if not block:
            return "{}"
        return json.dumps(_block_payload(addr, block))


class CFGWebViewer(QWidget):
    """Embeds cfg_render.html — interactive 3D graph with hover/click tooltips."""

    def __init__(self, program_model, parent=None):
        super().__init__(parent)
        self.program_model = program_model
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        if not WEBENGINE:
            from PyQt6.QtWidgets import QLabel
            layout.addWidget(QLabel("PyQt6-WebEngine not installed — pip install PyQt6-WebEngine"))
            return
        try:
            self.view = QWebEngineView(self)
        except Exception as exc:
            from PyQt6.QtWidgets import QLabel
            layout.addWidget(QLabel(f"WebEngine unavailable: {exc}"))
            return
        settings = self.view.page().settings()
        settings.setAttribute(QWebEngineSettings.WebAttribute.JavascriptEnabled, True)
        settings.setAttribute(QWebEngineSettings.WebAttribute.LocalContentCanAccessFileUrls, True)
        settings.setAttribute(QWebEngineSettings.WebAttribute.LocalContentCanAccessRemoteUrls, True)

        self.channel = QWebChannel(self)
        self.bridge = GraphBridge(program_model)
        self.channel.registerObject("py_bridge", self.bridge)
        self.view.page().setWebChannel(self.channel)

        self.view.page().loadFinished.connect(self._inject_graph)
        html = os.path.join(project_root(), "assets", "web", "cfg_render.html")
        self.view.load(QUrl.fromLocalFile(os.path.abspath(html)))
        layout.addWidget(self.view)

    def _inject_graph(self, ok: bool):
        """Push graph JSON into the page — reliable vs QWebChannel-only on file:// URLs."""
        if not ok:
            self.view.page().runJavaScript(
                "window.__cfgError && window.__cfgError('Failed to load CFG viewer page');"
            )
            return
        payload = self.bridge.get_graph_data()
        # Pass JSON directly — json.dumps output is valid JS literal for objects.
        self.view.page().runJavaScript(f"window.__loadGraph({payload});")


def available():
    """True when WebEngine can be used interactively (not in CI offscreen mode)."""
    import os
    if os.environ.get("QT_QPA_PLATFORM", "").lower() == "offscreen":
        return False
    return WEBENGINE
