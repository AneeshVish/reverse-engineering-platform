from PyQt6.QtWidgets import QWidget, QVBoxLayout
from PyQt6.QtCore import Qt
import networkx as nx
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from src.core.cfg import CFGGenerator

class CFGViewer(QWidget):
    def __init__(self, instructions, parent=None):
        super().__init__(parent)
        self.instructions = instructions
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        self.figure, self.ax = plt.subplots()
        self.canvas = FigureCanvas(self.figure)
        layout.addWidget(self.canvas)
        self.draw_cfg()

    def draw_cfg(self):
        cfg_gen = CFGGenerator()
        G = cfg_gen.build_cfg(self.instructions)
        self.ax.clear()
        pos = nx.spring_layout(G)
        nx.draw(G, pos, ax=self.ax, with_labels=True, node_size=500, node_color='lightblue', font_size=8)
        labels = nx.get_node_attributes(G, 'mnemonic')
        nx.draw_networkx_labels(G, pos, labels=labels, font_size=7)
        self.canvas.draw()
