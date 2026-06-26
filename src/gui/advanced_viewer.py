import sys
import numpy as np
import pandas as pd
from PyQt6.QtWidgets import *
from PyQt6.QtCore import *
from PyQt6.QtGui import *
import pyqtgraph as pg
import networkx as nx
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure

from src.core.decompiler_manager import DecompilerEngine

class AdvancedVisualizationWidget(QWidget):
    """Advanced visualization for binary analysis with PyQtGraph and NetworkX [15][20][23][25]"""
    
    def __init__(self):
        super().__init__()
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Create tab widget for different visualizations
        self.viz_tabs = QTabWidget()
        
        # Control Flow Graph visualization
        self.cfg_widget = self.create_cfg_widget()
        self.viz_tabs.addTab(self.cfg_widget, "Control Flow Graph")
        
        # Binary entropy visualization
        self.entropy_widget = self.create_entropy_widget()
        self.viz_tabs.addTab(self.entropy_widget, "Entropy Analysis")
        
        # Function call graph
        self.call_graph_widget = self.create_call_graph_widget()
        self.viz_tabs.addTab(self.call_graph_widget, "Call Graph")
        
        # Memory layout visualization
        self.memory_widget = self.create_memory_widget()
        self.viz_tabs.addTab(self.memory_widget, "Memory Layout")
        
        layout.addWidget(self.viz_tabs)
        self.setLayout(layout)
    
    def create_cfg_widget(self):
        """Create Control Flow Graph visualization using NetworkX [25]"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # PyQtGraph for interactive CFG
        self.cfg_view = pg.GraphicsLayoutWidget()
        self.cfg_plot = self.cfg_view.addPlot()
        self.cfg_plot.setLabel('left', 'Basic Blocks')
        self.cfg_plot.setLabel('bottom', 'Control Flow')
        
        layout.addWidget(self.cfg_view)
        widget.setLayout(layout)
        return widget
    
    def create_entropy_widget(self):
        """Create binary entropy visualization [20]"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Matplotlib canvas for entropy plot
        self.entropy_figure = Figure(figsize=(12, 8))
        self.entropy_canvas = FigureCanvas(self.entropy_figure)
        layout.addWidget(self.entropy_canvas)
        
        # Controls
        controls = QHBoxLayout()
        controls.addWidget(QLabel("Window Size:"))
        self.window_size_spin = QSpinBox()
        self.window_size_spin.setRange(32, 4096)
        self.window_size_spin.setValue(256)
        self.window_size_spin.valueChanged.connect(self.update_entropy_plot)
        controls.addWidget(self.window_size_spin)
        
        controls.addStretch()
        layout.addLayout(controls)
        
        widget.setLayout(layout)
        return widget
    
    def create_call_graph_widget(self):
        """Create function call graph visualization [25]"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # PyQtGraph for interactive call graph
        self.call_graph_view = pg.GraphicsLayoutWidget()
        layout.addWidget(self.call_graph_view)
        
        widget.setLayout(layout)
        return widget
    
    def create_memory_widget(self):
        """Create memory layout visualization"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Custom memory map widget
        self.memory_view = MemoryMapWidget()
        layout.addWidget(self.memory_view)
        
        widget.setLayout(layout)
        return widget
    
    def update_cfg(self, basic_blocks):
        """Update Control Flow Graph with basic blocks data [25]"""
        if not basic_blocks:
            return
        
        # Limit the number of nodes to prevent UI freezing
        MAX_NODES = 200
        if len(basic_blocks) > MAX_NODES:
            # Show only the first MAX_NODES nodes
            shown_blocks = basic_blocks[:MAX_NODES]
            import logging
            logging.getLogger(__name__).warning(
                f"[Visualization] Too many basic blocks ({len(basic_blocks)}). Showing only the first {MAX_NODES}."
            )
            # Optionally, show a warning in the UI if you have a log panel:
            if hasattr(self, 'parent') and hasattr(self.parent(), 'log_view'):
                self.parent().log_view.append(
                    f"[WARNING] Too many basic blocks ({len(basic_blocks)}). Showing only the first {MAX_NODES} in CFG visualization."
                )
        else:
            shown_blocks = basic_blocks
        
        # Create NetworkX graph
        G = nx.DiGraph()
        
        # Add nodes (basic blocks)
        for bb in shown_blocks:
            G.add_node(bb['address'], 
                      size=bb.get('size', 10),
                      instructions=bb.get('instructions', []))
        
        # Add edges (control flow)
        for bb in shown_blocks:
            for target in bb.get('targets', []):
                if target in [b['address'] for b in shown_blocks]:
                    G.add_edge(bb['address'], target)
        
        # Use spring layout for positioning
        pos = nx.spring_layout(G, seed=42)
        
        # Clear and redraw
        self.cfg_plot.clear()
        
        # Draw nodes
        x_pos = [pos[node][0] for node in G.nodes()]
        y_pos = [pos[node][1] for node in G.nodes()]
        
        scatter = pg.ScatterPlotItem(
            x=x_pos, y=y_pos, 
            size=10, pen=pg.mkPen('w'), brush=pg.mkBrush('b')
        )
        self.cfg_plot.addItem(scatter)
        
        # Draw edges
        for edge in G.edges():
            x_data = [pos[edge[0]][0], pos[edge[1]][0]]
            y_data = [pos[edge[0]][1], pos[edge[1]][1]]
            line = pg.PlotDataItem(x_data, y_data, pen=pg.mkPen('w', width=1))
            self.cfg_plot.addItem(line)
    
    def update_entropy_plot(self):
        """Update entropy analysis plot [20]"""
        window_size = self.window_size_spin.value()
        
        # Calculate entropy for loaded binary
        if hasattr(self, 'binary_data') and self.binary_data:
            entropy_data = self.calculate_entropy(self.binary_data, window_size)
            
            self.entropy_figure.clear()
            ax = self.entropy_figure.add_subplot(111)
            
            ax.plot(entropy_data, color='red', linewidth=1)
            ax.set_title(f'Binary Entropy Analysis (Window Size: {window_size})')
            ax.set_xlabel('Byte Offset')
            ax.set_ylabel('Entropy')
            ax.grid(True, alpha=0.3)
            
            # Highlight high entropy regions (potential packed/encrypted sections)
            high_entropy_threshold = 7.5
            high_entropy_regions = np.where(entropy_data > high_entropy_threshold)[0]
            
            if len(high_entropy_regions) > 0:
                ax.scatter(high_entropy_regions, 
                          entropy_data[high_entropy_regions], 
                          color='yellow', s=10, alpha=0.7,
                          label='High Entropy (Possible Packing)')
                ax.legend()
            
            self.entropy_canvas.draw()
    
    def calculate_entropy(self, data, window_size):
        """Calculate Shannon entropy for binary data"""
        if isinstance(data, str):
            data = data.encode()
        
        entropy_values = []
        
        for i in range(0, len(data) - window_size + 1, window_size // 4):
            window = data[i:i + window_size]
            
            # Calculate frequency of each byte value
            byte_counts = np.bincount(window)
            probabilities = byte_counts[byte_counts > 0] / len(window)
            
            # Calculate Shannon entropy
            entropy = -np.sum(probabilities * np.log2(probabilities))
            entropy_values.append(entropy)
        
        return np.array(entropy_values)
    
    def set_binary_data(self, data):
        """Set binary data for analysis"""
        self.binary_data = data
        self.update_entropy_plot()

class MemoryMapWidget(QWidget):
    """Custom widget for visualizing memory layout"""
    
    def __init__(self):
        super().__init__()
        self.sections = []
        self.setMinimumHeight(200)
    
    def set_sections(self, sections):
        """Set memory sections to visualize"""
        self.sections = sections
        self.update()
    
    def paintEvent(self, event):
        """Paint memory layout visualization"""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        if not self.sections:
            painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, "No sections loaded")
            return
        
        # Calculate total memory range
        min_addr = min(section.virtual_address for section in self.sections)
        max_addr = max(section.virtual_address + section.size for section in self.sections)
        total_size = max_addr - min_addr
        
        # Define colors for different section types
        section_colors = {
            '.text': QColor(255, 100, 100),    # Red for code
            '.data': QColor(100, 255, 100),    # Green for data
            '.bss': QColor(100, 100, 255),     # Blue for BSS
            '.rodata': QColor(255, 255, 100),  # Yellow for read-only data
        }
        
        # Draw sections
        widget_width = self.width() - 40
        widget_height = self.height() - 40
        
        for section in self.sections:
            # Calculate position and size
            x_offset = int((section.virtual_address - min_addr) / total_size * widget_width)
            width = max(1, int(section.size / total_size * widget_width))
            
            # Get color based on section name
            color = section_colors.get(section.name, QColor(150, 150, 150))
            painter.fillRect(20 + x_offset, 20, width, widget_height, color)
            
            # Draw section label if there's space
            if width > 50:
                painter.setPen(QColor(0, 0, 0))
                text_rect = QRect(20 + x_offset, 20, width, 20)
                painter.drawText(text_rect, Qt.AlignmentFlag.AlignCenter, section.name)
        
        # Draw address labels
        painter.setPen(QColor(0, 0, 0))
        painter.drawText(10, 15, f"0x{min_addr:08x}")
        painter.drawText(self.width() - 80, 15, f"0x{max_addr:08x}")

class AIAnalysisPanel(QWidget):
    """Panel for displaying AI-powered analysis results [6][9]"""
    
    def __init__(self):
        super().__init__()
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        # AI analysis tabs
        self.ai_tabs = QTabWidget()
        
        # LLM4Decompile results
        self.llm_view = QTextEdit()
        self.llm_view.setReadOnly(True)
        self.ai_tabs.addTab(self.llm_view, "LLM4Decompile")
        
        # Traditional decompilation
        self.traditional_view = QTextEdit()
        self.traditional_view.setReadOnly(True)
        self.ai_tabs.addTab(self.traditional_view, "Traditional")
        
        # Consensus view
        self.consensus_view = QTextEdit()
        self.consensus_view.setReadOnly(True)
        self.ai_tabs.addTab(self.consensus_view, "Consensus")
        
        # Analysis comparison
        self.comparison_view = QTextEdit()
        self.comparison_view.setReadOnly(True)
        self.ai_tabs.addTab(self.comparison_view, "Comparison")
        
        layout.addWidget(self.ai_tabs)
        
        # Control buttons
        controls = QHBoxLayout()

        self.reanalyze_btn = QPushButton("Re-analyze with AI")
        self.export_btn = QPushButton("Export Results")
        self.enhance_btn = QPushButton("Enhance with Comments")
        self.summarize_btn = QPushButton("Summarize Function")
        self.qa_btn = QPushButton("Ask AI")

        # Language selection dropdown
        self.language_combo = QComboBox()
        self.language_combo.addItems(["C", "C++", "Java", "Python"])
        self.language_combo.setCurrentText("C")

        controls.addWidget(QLabel("Target Language:"))
        controls.addWidget(self.language_combo)
        controls.addWidget(self.reanalyze_btn)
        controls.addWidget(self.export_btn)
        controls.addWidget(self.enhance_btn)
        controls.addWidget(self.summarize_btn)
        controls.addWidget(self.qa_btn)
        controls.addStretch()

        layout.addLayout(controls)
        self.setLayout(layout)
    
    def update_analysis_results(self, results):
        """Update AI analysis results [6]"""
        if DecompilerEngine.LLM4DECOMPILE in results:
            llm_result = results[DecompilerEngine.LLM4DECOMPILE]
            if llm_result.get('success'):
                self.llm_view.setPlainText(llm_result['code'])
            else:
                self.llm_view.setPlainText(f"Error: {llm_result.get('error', 'Unknown error')}")
        
        if 'consensus' in results:
            self.consensus_view.setPlainText(results['consensus'])
        
        # Generate comparison
        comparison_text = self.generate_comparison(results)
        self.comparison_view.setPlainText(comparison_text)
    
    def generate_comparison(self, results):
        """Generate comparison analysis between different decompilation methods"""
        comparison = "# Decompilation Analysis Comparison\n\n"
        
        successful_engines = [k for k, v in results.items() if isinstance(v, dict) and v.get('success', False)]
        
        comparison += f"## Successful Engines: {len(successful_engines)}\n"
        for engine in successful_engines:
            result = results[engine]
            lines = len(result['code'].split('\n'))
            comparison += f"- {engine.value}: {lines} lines\n"
        
        comparison += f"\n## Analysis Summary\n"
        comparison += f"- LLM4Decompile provides more human-readable output\n"
        comparison += f"- Traditional tools may be more technically accurate\n"
        comparison += f"- Consensus view combines best of all methods\n"
        
        return comparison
