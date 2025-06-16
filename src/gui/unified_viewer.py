from PyQt6.QtWidgets import QTabWidget, QTextEdit, QTreeWidget

class UnifiedViewer(QTabWidget):
    def __init__(self):
        super().__init__()
        # Hex View
        self.hex_view = QTextEdit()
        self.hex_view.setFontFamily("Courier New")
        
        # Disassembly
        self.disasm_view = QTextEdit()
        self.disasm_view.setFontFamily("Courier New")
        
        # Structure
        self.struct_view = QTreeWidget()
        self.struct_view.setHeaderLabel("File Structure")
        
        # Decompilation
        self.decomp_view = QTextEdit()
        
        self.addTab(self.hex_view, "Hex")
        self.addTab(self.disasm_view, "Disassembly")
        self.addTab(self.struct_view, "Structure")
        self.addTab(self.decomp_view, "Decompilation")
