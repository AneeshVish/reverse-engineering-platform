"""
Project Storage Module for Reverse Engineering Platform

This module handles the storage and organization of decompiled project data
for use in AI analysis and project reconstruction.
"""
import os
import json
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

class ProjectStorage:
    def __init__(self, storage_dir="decompiled_projects"):
        """Initialize project storage with a base directory"""
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(exist_ok=True, parents=True)
        logger.info(f"Project storage initialized at {self.storage_dir}")

    def save_project_data(self, project_name, data):
        """Save comprehensive project data to storage"""
        project_dir = self.storage_dir / project_name
        project_dir.mkdir(exist_ok=True, parents=True)
        
        # Save full project data
        project_file = project_dir / "project_data.json"
        with open(project_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
        logger.info(f"Saved project data for {project_name}")
        
        return str(project_file)

    def load_project_data(self, project_name):
        """Load project data from storage"""
        project_file = self.storage_dir / project_name / "project_data.json"
        if project_file.exists():
            with open(project_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        return None

    def generate_project_summary(self, project_name):
        """Generate a summary text file of the project for AI analysis"""
        data = self.load_project_data(project_name)
        if not data:
            return None
        
        summary_path = self.storage_dir / project_name / "project_summary.txt"
        with open(summary_path, 'w', encoding='utf-8') as f:
            f.write(f"# Decompiled Project Summary: {project_name}\n\n")
            f.write("## Project Overview\n")
            f.write(f"- Name: {data.get('name', 'N/A')}\n")
            f.write(f"- Type: {data.get('type', 'N/A')}\n")
            f.write(f"- Original Platform: {data.get('platform', 'N/A')}\n")
            f.write(f"- File Size: {data.get('file_size', 'N/A')}\n\n")
            
            f.write("## Architecture\n")
            f.write(f"- Binary Format: {data.get('binary_format', 'N/A')}\n")
            f.write(f"- Architecture: {data.get('architecture', 'N/A')}\n")
            f.write(f"- Endianness: {data.get('endianness', 'N/A')}\n\n")
            
            f.write("## Components\n")
            for component in data.get('components', []):
                f.write(f"### {component.get('name', 'Unnamed Component')}\n")
                f.write(f"- Type: {component.get('type', 'N/A')}\n")
                f.write(f"- Purpose: {component.get('purpose', 'N/A')}\n")
                code_snippet = component.get('code_snippet', 'N/A')
                if code_snippet != 'N/A':
                    f.write("- Code Sample:\n")
                    f.write("```c\n")
                    f.write(code_snippet[:500] + "..." if len(code_snippet) > 500 else code_snippet)
                    f.write("\n```\n")
                f.write("- Key Functions:\n")
                for func in component.get('functions', [])[:5]:  # Limit to 5 functions
                    f.write(f"  - {func.get('name', 'Unnamed Function')}: {func.get('description', 'N/A')}\n")
                f.write("\n")
            
            f.write("## Dependencies\n")
            for dep in data.get('dependencies', []):
                f.write(f"- {dep.get('name', 'N/A')}: {dep.get('version', 'N/A')}\n")
            f.write("\n")
            
            f.write("## Security Findings\n")
            for finding in data.get('security_findings', []):
                f.write(f"- {finding.get('type', 'N/A')}: {finding.get('description', 'N/A')}\n")
            f.write("\n")
            
            f.write("## Reconstruction Notes\n")
            f.write(data.get('reconstruction_notes', 'No reconstruction notes available.'))
        
        logger.info(f"Generated project summary for {project_name}")
        return str(summary_path)

    def get_project_list(self):
        """Return a list of stored projects"""
        return [d.name for d in self.storage_dir.iterdir() if d.is_dir()]
