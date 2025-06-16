# -*- coding: utf-8 -*-

import logging
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTreeWidget, 
                             QTreeWidgetItem, QTableWidget, QTableWidgetItem, 
                             QTextEdit, QLabel, QPushButton, QListWidget, 
                             QListWidgetItem, QScrollArea, QFrame)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont

class DisassemblyView(QWidget):
    '''Widget for displaying disassembly'''
    
    def __init__(self):
        super().__init__()
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout(self)
        
        # Create table for disassembly
        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(['Address', 'Bytes', 'Mnemonic', 'Operands'])
        
        # Set font for disassembly
        font = QFont("Consolas", 9)
        self.table.setFont(font)
        
        layout.addWidget(self.table)
    
    def update_disassembly(self, instructions):
        '''Update the disassembly view with instructions'''
        self.table.setRowCount(len(instructions))
        
        for i, instruction in enumerate(instructions):
            # Address
            address_item = QTableWidgetItem(f"0x{instruction['address']:08x}")
            address_item.setFlags(Qt.ItemFlag.ItemIsSelectable | Qt.ItemFlag.ItemIsEnabled)
            self.table.setItem(i, 0, address_item)
            
            # Bytes
            bytes_str = ' '.join(f'{b:02x}' for b in instruction['bytes'])
            bytes_item = QTableWidgetItem(bytes_str)
            bytes_item.setFlags(Qt.ItemFlag.ItemIsSelectable | Qt.ItemFlag.ItemIsEnabled)
            self.table.setItem(i, 1, bytes_item)
            
            # Mnemonic
            mnemonic_item = QTableWidgetItem(instruction['mnemonic'])
            mnemonic_item.setFlags(Qt.ItemFlag.ItemIsSelectable | Qt.ItemFlag.ItemIsEnabled)
            self.table.setItem(i, 2, mnemonic_item)
            
            # Operands
            operands_item = QTableWidgetItem(instruction['op_str'])
            operands_item.setFlags(Qt.ItemFlag.ItemIsSelectable | Qt.ItemFlag.ItemIsEnabled)
            self.table.setItem(i, 3, operands_item)
        
        # Resize columns to content
        self.table.resizeColumnsToContents()

class BinaryInfoView(QWidget):
    '''Widget for displaying binary information'''
    
    def __init__(self):
        super().__init__()
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout(self)
        
        # Create tree widget for binary info
        self.tree = QTreeWidget()
        self.tree.setHeaderLabel("Binary Information")
        layout.addWidget(self.tree)
    
    def update_info(self, binary_info, sections):
        '''Update the binary info view'''
        self.tree.clear()
        
        # Basic info
        basic_info = QTreeWidgetItem(self.tree)
        basic_info.setText(0, "Basic Information")
        
        for key, value in binary_info.items():
            if key not in ['sections', 'segments', 'imports', 'dynamic_entries']:
                item = QTreeWidgetItem(basic_info)
                item.setText(0, f"{key}: {value}")
        
        basic_info.setExpanded(True)
        
        # Sections
        if 'sections' in binary_info:
            sections_item = QTreeWidgetItem(self.tree)
            sections_item.setText(0, "Sections")
            
            for section in binary_info['sections']:
                section_item = QTreeWidgetItem(sections_item)
                section_item.setText(0, section['name'])
                
                # Section details
                details = [
                    f"Size: 0x{section['size']:x}",
                    f"Virtual Address: 0x{section['virtual_address']:x}"
                ]
                
                for detail in details:
                    detail_item = QTreeWidgetItem(section_item)
                    detail_item.setText(0, detail)
            
            sections_item.setExpanded(False)
        
        # Imports (for PE files)
        if 'imports' in binary_info:
            imports_item = QTreeWidgetItem(self.tree)
            imports_item.setText(0, "Imports")
            
            for import_entry in binary_info['imports']:
                dll_item = QTreeWidgetItem(imports_item)
                dll_item.setText(0, import_entry['name'])
                
                for function in import_entry['functions']:
                    func_item = QTreeWidgetItem(dll_item)
                    func_item.setText(0, function)
            
            imports_item.setExpanded(False)

class PluginView(QWidget):
    '''Widget for displaying and managing plugins'''
    
    def __init__(self, plugin_manager):
        super().__init__()
        self.plugin_manager = plugin_manager
        self.init_ui()
        self.update_plugins()
    
    def init_ui(self):
        layout = QVBoxLayout(self)
        
        # Plugin list
        self.plugin_list = QListWidget()
        layout.addWidget(self.plugin_list)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        self.refresh_button = QPushButton("Refresh")
        self.refresh_button.clicked.connect(self.update_plugins)
        button_layout.addWidget(self.refresh_button)
        
        layout.addLayout(button_layout)
    
    def update_plugins(self):
        '''Update the plugin list'''
        self.plugin_list.clear()
        
        plugins = self.plugin_manager.get_plugins()
        for plugin_name, plugin in plugins.items():
            info = plugin.get_info()
            item_text = f"{info['name']} v{info['version']} - {info['description']}"
            item = QListWidgetItem(item_text)
            self.plugin_list.addItem(item)
