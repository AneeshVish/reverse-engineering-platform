"""
Project Analysis Tab for Reverse Engineering Platform

This module provides a comprehensive tab for advanced project analysis
and AI-assisted reconstruction capabilities.
"""
import os
import json
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QPushButton, QTextEdit, 
                            QLabel, QHBoxLayout, QMessageBox, QFileDialog)
from PyQt6.QtCore import Qt
from src.utils.project_storage import ProjectStorage
from src.ai.prompt_generator import PromptGenerator
import logging

logger = logging.getLogger(__name__)

class ProjectAnalysisTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.storage = ProjectStorage()
        self.prompt_generator = PromptGenerator()
        self.current_project = None
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        # Title
        title_label = QLabel("Project Analysis & Reconstruction")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_label.setStyleSheet("font-size: 18px; font-weight: bold; margin: 10px;")
        layout.addWidget(title_label)

        # Main control area
        controls_layout = QHBoxLayout()
        
        self.analyze_btn = QPushButton("Analyze Project")
        self.analyze_btn.setToolTip("Perform a comprehensive analysis of the current project")
        self.analyze_btn.clicked.connect(self.analyze_project)
        controls_layout.addWidget(self.analyze_btn)
        
        self.generate_prompt_btn = QPushButton("Generate Prompt")
        self.generate_prompt_btn.setToolTip("Generate a detailed prompt for AI reconstruction of the decompiled project")
        self.generate_prompt_btn.clicked.connect(self.generate_prompt)
        self.generate_prompt_btn.setEnabled(False)
        controls_layout.addWidget(self.generate_prompt_btn)
        
        self.save_btn = QPushButton("Save Analysis")
        self.save_btn.setToolTip("Save the current analysis results")
        self.save_btn.clicked.connect(self.save_analysis)
        self.save_btn.setEnabled(False)
        controls_layout.addWidget(self.save_btn)
        
        layout.addLayout(controls_layout)

        # Analysis results display
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        self.results_text.setPlaceholderText("Project analysis results will appear here...")
        layout.addWidget(self.results_text)

        self.setLayout(layout)

    def set_current_project(self, project_data):
        """Set the current project for analysis"""
        self.current_project = project_data
        self.generate_prompt_btn.setEnabled(bool(project_data))
        self.save_btn.setEnabled(bool(project_data))
        if project_data:
            self.results_text.setText("Project loaded. Click 'Analyze Project' to perform detailed analysis.")
        else:
            self.results_text.clear()

    def analyze_project(self):
        """Perform a comprehensive analysis of the current project"""
        if not self.current_project:
            QMessageBox.warning(self, "No Project", "No project loaded for analysis.")
            return
        
        self.results_text.setText("Analyzing project... This may take a while.")
        try:
            # Extract project details (this is a placeholder for actual analysis)
            project_name = self.current_project.get('name', 'unnamed_project')
            analysis_results = f"Comprehensive analysis for {project_name}:\n\n"
            analysis_results += f"Platform: {self.current_project.get('platform', 'N/A')}\n"
            analysis_results += f"Architecture: {self.current_project.get('architecture', 'N/A')}\n"
            analysis_results += f"Components: {len(self.current_project.get('components', []))}\n"
            analysis_results += f"Security Issues: {len(self.current_project.get('security_findings', []))}\n"
            
            self.results_text.setText(analysis_results)
            logger.info(f"Completed analysis for project {project_name}")
        except Exception as e:
            logger.error(f"Error analyzing project: {str(e)}")
            self.results_text.setText(f"Error during analysis: {str(e)}")

    def generate_prompt(self):
        """Generate a detailed prompt for AI reconstruction"""
        if not self.current_project:
            QMessageBox.warning(self, "No Project", "No project loaded for prompt generation.")
            return
        
        try:
            project_name = self.current_project.get('name', 'unnamed_project')
            self.results_text.setText(f"Generating reconstruction prompt for {project_name}...")
            
            # Save project data to storage first
            self.storage.save_project_data(project_name, self.current_project)
            
            # Generate the prompt
            prompt_path = self.prompt_generator.generate_reconstruction_prompt(project_name)
            if prompt_path:
                self.results_text.setText(f"Generated reconstruction prompt at: {prompt_path}\n\n"
                                        f"You can use this prompt with AI systems like Cursor or Windsurf "
                                        f"to reconstruct the decompiled project.")
                logger.info(f"Generated prompt for {project_name} at {prompt_path}")
            else:
                self.results_text.setText("Failed to generate prompt. Check logs for details.")
                logger.error(f"Failed to generate prompt for {project_name}")
        except Exception as e:
            logger.error(f"Error generating prompt: {str(e)}")
            self.results_text.setText(f"Error generating prompt: {str(e)}")

    def save_analysis(self):
        """Save the current analysis results"""
        if not self.current_project:
            QMessageBox.warning(self, "No Project", "No project data to save.")
            return
        
        try:
            project_name = self.current_project.get('name', 'unnamed_project')
            save_path = QFileDialog.getSaveFileName(self, "Save Analysis", f"{project_name}_analysis.txt", "Text Files (*.txt)")[0]
            if save_path:
                with open(save_path, 'w', encoding='utf-8') as f:
                    f.write(self.results_text.toPlainText())
                logger.info(f"Saved analysis for {project_name} to {save_path}")
                QMessageBox.information(self, "Saved", f"Analysis saved to {save_path}")
        except Exception as e:
            logger.error(f"Error saving analysis: {str(e)}")
            QMessageBox.critical(self, "Error", f"Failed to save analysis: {str(e)}")
