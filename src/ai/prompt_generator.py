"""
AI Prompt Generator for Reverse Engineering Platform

This module generates comprehensive prompts for AI systems to reconstruct
decompiled projects from stored analysis data.
"""
import os
import logging
from pathlib import Path
import requests
import json

# Read configuration file for AI settings
CONFIG_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'config.json')

def load_ai_config():
    """Load AI configuration from config.json"""
    try:
        with open(CONFIG_FILE, 'r') as f:
            config = json.load(f)
            return config.get('ai', {})
    except Exception as e:
        logger.error(f"Error loading AI config from {CONFIG_FILE}: {str(e)}")
        return {}

from src.utils.project_storage import ProjectStorage

logger = logging.getLogger(__name__)

class PromptGenerator:
    def __init__(self, storage_dir="decompiled_projects", ollama_endpoint="http://localhost:11434/api/generate"):
        """Initialize prompt generator with project storage and Ollama endpoint"""
        self.storage = ProjectStorage(storage_dir)
        self.ollama_endpoint = ollama_endpoint
        logger.info("Prompt generator initialized")

    def _call_ollama(self, prompt, model=None):
        """Helper method to call Ollama API with a prompt"""
        if model is None:
            ai_config = load_ai_config()
            model = ai_config.get('model', 'llama3')
            logger.info(f"Using model from config: {model}")
        try:
            payload = {
                "model": model,
                "prompt": prompt,
                "stream": False
            }
            response = requests.post(self.ollama_endpoint, json=payload, timeout=60)
            if response.status_code == 200:
                return response.json().get("response", "")
            else:
                logger.error(f"Ollama API returned status code {response.status_code}")
                return ""
        except Exception as e:
            logger.error(f"Error calling Ollama API: {str(e)}")
            return ""

    def generate_reconstruction_prompt(self, project_name, use_ollama=True, stages=3):
        """Generate a detailed prompt for project reconstruction, optionally using Ollama in stages"""
        project_data = self.storage.load_project_data(project_name)
        if not project_data:
            logger.error(f"No project data found for {project_name}")
            return None

        prompt_path = self.storage.storage_dir / project_name / "reconstruction_prompt.txt"
        try:
            with open(prompt_path, 'w', encoding='utf-8') as f:
                f.write("# Project Reconstruction Prompt\n\n")
                f.write("You are an expert software engineer tasked with reconstructing a decompiled software project. "
                        "Below is a detailed analysis of the original binary. Your goal is to recreate a functional "
                        "version of this software using modern programming practices and the information provided. "
                        "Please provide complete source code with appropriate comments and documentation. If any "
                        "information is missing or unclear, make reasonable assumptions and document them clearly.\n\n")
                
                f.write("## Project Identification\n")
                f.write("- Project Name: {}\n".format(project_data.get('name', 'Unknown')))
                f.write("- Software Type: {}\n".format(project_data.get('type', 'Unknown')))
                f.write("- Original Platform: {}\n".format(project_data.get('platform', 'Unknown')))
                f.write("- File Size: {}\n\n".format(project_data.get('file_size', 'Unknown')))
                
                f.write("## Technical Specifications\n")
                f.write("- Binary Format: {}\n".format(project_data.get('binary_format', 'Unknown')))
                f.write("- Architecture: {}\n".format(project_data.get('architecture', 'Unknown')))
                f.write("- Endianness: {}\n".format(project_data.get('endianness', 'Unknown')))
                f.write("- Entry Point: {}\n\n".format(project_data.get('entry_point', 'Unknown')))
                
                if use_ollama:
                    # Stage 1: Initial analysis by Ollama
                    stage1_prompt = (
                        "I am reconstructing a decompiled software project. Here is the basic information:\n"
                        f"Project Name: {project_data.get('name', 'Unknown')}\n"
                        f"Software Type: {project_data.get('type', 'Unknown')}\n"
                        f"Original Platform: {project_data.get('platform', 'Unknown')}\n"
                        f"Binary Format: {project_data.get('binary_format', 'Unknown')}\n"
                        f"Architecture: {project_data.get('architecture', 'Unknown')}\n"
                        "Please provide an initial analysis of what kind of software this might be and suggest a "
                        "high-level structure for reconstruction. Limit your response to 500 words."
                    )
                    stage1_response = self._call_ollama(stage1_prompt)
                    if stage1_response:
                        f.write("## Initial AI Analysis (Stage 1 of {})\n".format(stages))
                        f.write(stage1_response + "\n\n")
                    else:
                        f.write("## Initial AI Analysis (Stage 1 of {})\n".format(stages))
                        f.write("AI analysis unavailable due to connection issues with Ollama.\n\n")
                        logger.warning("Stage 1 Ollama response not obtained")
                
                f.write("## Project Components and Structure\n")
                f.write("The original software was composed of the following components. Please recreate each component "
                        "with the described functionality. Pay attention to the relationships between components.\n\n")
                for idx, component in enumerate(project_data.get('components', []), 1):
                    f.write("### Component {}: {}\n".format(idx, component.get('name', 'Component_{}'.format(idx))))
                    f.write("- Type: {}\n".format(component.get('type', 'Unknown')))
                    f.write("- Purpose: {}\n".format(component.get('purpose', 'No description available')))
                    if 'code_snippet' in component and component['code_snippet']:
                        f.write("- Decompiled Code Sample:\n")
                        f.write("```\n")
                        f.write(component['code_snippet'][:1000] + "..." if len(component['code_snippet']) > 1000 else component['code_snippet'])
                        f.write("\n```\n")
                    f.write("- Key Functions and Behaviors:\n")
                    for func in component.get('functions', []):
                        f.write("  - Function: {}\n".format(func.get('name', 'Unnamed')))
                        f.write("    - Description: {}\n".format(func.get('description', 'No description')))
                        f.write("    - Parameters: {}\n".format(func.get('parameters', 'Unknown')))
                        f.write("    - Return Value: {}\n".format(func.get('return', 'Unknown')))
                    f.write("- Relationships:\n")
                    for rel in component.get('relationships', []):
                        f.write("  - {}: {}\n".format(rel.get('type', 'Interacts with'), rel.get('target', 'Unknown component')))
                    f.write("\n")
                
                if use_ollama and len(project_data.get('components', [])) > 0:
                    # Stage 2: Component analysis by Ollama
                    stage2_prompt = (
                        "I am reconstructing a decompiled software project and have identified the following components:\n"
                    )
                    for idx, component in enumerate(project_data.get('components', []), 1):
                        stage2_prompt += (f"Component {idx}: {component.get('name', 'Component_{idx}')}\n"
                                        f"- Type: {component.get('type', 'Unknown')}\n"
                                        f"- Purpose: {component.get('purpose', 'No description available')}\n")
                    stage2_prompt += (
                        "Please provide a detailed analysis of how these components might interact and suggest an "
                        "architecture for the reconstructed software. Limit your response to 1000 words."
                    )
                    stage2_response = self._call_ollama(stage2_prompt)
                    if stage2_response:
                        f.write("## Component Architecture Analysis (Stage 2 of {})\n".format(stages))
                        f.write(stage2_response + "\n\n")
                    else:
                        f.write("## Component Architecture Analysis (Stage 2 of {})\n".format(stages))
                        f.write("AI analysis unavailable due to connection issues with Ollama.\n\n")
                        logger.warning("Stage 2 Ollama response not obtained")
                
                f.write("## External Dependencies\n")
                f.write("The software relied on the following external libraries or system components. Please include "
                        "equivalent modern alternatives if the original dependencies are outdated or unavailable.\n")
                for dep in project_data.get('dependencies', []):
                    f.write("- {}\n".format(dep.get('name', 'Unknown')))
                    f.write("  - Version: {}\n".format(dep.get('version', 'Unknown')))
                    f.write("  - Purpose: {}\n".format(dep.get('purpose', 'No description')))
                if not project_data.get('dependencies'):
                    f.write("No external dependencies identified.\n")
                f.write("\n")
                
                f.write("## Resources and Assets\n")
                f.write("The following resources were embedded in the original binary. Please recreate or provide "
                        "placeholders for these resources.\n")
                for res in project_data.get('resources', []):
                    f.write("- {}\n".format(res.get('name', 'Unnamed Resource')))
                    f.write("  - Type: {}\n".format(res.get('type', 'Unknown')))
                    f.write("  - Size: {}\n".format(res.get('size', 'Unknown')))
                    f.write("  - Description: {}\n".format(res.get('description', 'No description')))
                if not project_data.get('resources'):
                    f.write("No embedded resources identified.\n")
                f.write("\n")
                
                f.write("## Security and Implementation Notes\n")
                f.write("During analysis, the following security issues or implementation details were noted. Please "
                        "address these in your reconstruction with modern secure coding practices.\n")
                for finding in project_data.get('security_findings', []):
                    f.write("- Issue: {}\n".format(finding.get('type', 'Unknown issue')))
                    f.write("  - Severity: {}\n".format(finding.get('severity', 'Unknown')))
                    f.write("  - Location: {}\n".format(finding.get('location', 'Unknown')))
                    f.write("  - Description: {}\n".format(finding.get('description', 'No description')))
                    f.write("  - Recommendation: {}\n".format(finding.get('recommendation', 'No recommendation')))
                if not project_data.get('security_findings'):
                    f.write("No security issues identified in the original binary.\n")
                f.write("\n")
                
                if use_ollama and len(project_data.get('security_findings', [])) > 0:
                    # Stage 3: Security analysis by Ollama
                    stage3_prompt = (
                        "I am reconstructing a decompiled software project and have identified the following security issues:\n"
                    )
                    for finding in project_data.get('security_findings', []):
                        stage3_prompt += (f"- Issue: {finding.get('type', 'Unknown issue')}\n"
                                        f"  - Severity: {finding.get('severity', 'Unknown')}\n"
                                        f"  - Description: {finding.get('description', 'No description')}\n")
                    stage3_prompt += (
                        "Please provide recommendations for addressing these security issues in a modern reconstruction "
                        "of the software. Suggest secure coding practices and modern alternatives to outdated methods. "
                        "Limit your response to 1000 words."
                    )
                    stage3_response = self._call_ollama(stage3_prompt)
                    if stage3_response:
                        f.write("## Security Recommendations (Stage 3 of {})\n".format(stages))
                        f.write(stage3_response + "\n\n")
                    else:
                        f.write("## Security Recommendations (Stage 3 of {})\n".format(stages))
                        f.write("AI analysis unavailable due to connection issues with Ollama.\n\n")
                        logger.warning("Stage 3 Ollama response not obtained")
                
                f.write("## Strings and User Interface Elements\n")
                f.write("These strings and UI elements provide insight into the application's interface and messaging. "
                        "Please incorporate these into your reconstruction.\n")
                for string in project_data.get('strings', [])[:50]:  # Limit to 50 strings
                    f.write("- \"{}\" - {}\n".format(string.get('value', ''), string.get('context', 'No context')))
                if len(project_data.get('strings', [])) > 50:
                    f.write("... and {} more strings not shown for brevity.\n".format(len(project_data.get('strings', [])) - 50))
                elif not project_data.get('strings'):
                    f.write("No significant strings extracted from the binary.\n")
                f.write("\n")
                
                f.write("## Control Flow and Algorithms\n")
                f.write("Key algorithms and control flow patterns identified in the decompiled code. Please implement "
                        "these core logic flows in your reconstruction.\n")
                for algo in project_data.get('algorithms', []):
                    f.write("- Algorithm: {}\n".format(algo.get('name', 'Unnamed algorithm')))
                    f.write("  - Purpose: {}\n".format(algo.get('purpose', 'No description')))
                    if 'pseudocode' in algo:
                        f.write("  - Pseudocode:\n")
                        f.write("    ```\n")
                        f.write(algo['pseudocode'])
                        f.write("    \n```\n")
                if not project_data.get('algorithms'):
                    f.write("No specific algorithms identified in the binary.\n")
                f.write("\n")
                
                f.write("## Network and Communication\n")
                f.write("Network behaviors and communication protocols observed during analysis. Please implement "
                        "equivalent functionality using modern APIs and secure protocols.\n")
                for endpoint in project_data.get('network_endpoints', []):
                    f.write("- Endpoint: {}\n".format(endpoint.get('url', 'Unknown')))
                    f.write("  - Type: {}\n".format(endpoint.get('type', 'Unknown')))
                    f.write("  - Purpose: {}\n".format(endpoint.get('purpose', 'No description')))
                    f.write("  - Data Sent: {}\n".format(endpoint.get('data_sent', 'No data identified')))
                    f.write("  - Data Received: {}\n".format(endpoint.get('data_received', 'No data identified')))
                if not project_data.get('network_endpoints'):
                    f.write("No network communications identified during analysis.\n")
                f.write("\n")
                
                f.write("## Reconstruction Guidance\n")
                f.write("Based on the analysis, here are specific instructions for reconstruction:\n")
                reconstruction_notes = project_data.get('reconstruction_notes', 'No specific notes provided.')
                f.write(reconstruction_notes if reconstruction_notes else "Use best judgment based on the information above.\n")
                f.write("\n\n")
                
                f.write("## Deliverables\n")
                f.write("Please provide the following as part of your reconstruction:\n")
                f.write("1. Complete source code in a modern, appropriate programming language\n")
                f.write("2. Project structure with build instructions\n")
                f.write("3. Documentation explaining design decisions and assumptions\n")
                f.write("4. Any necessary configuration files or environment setup instructions\n")
                f.write("5. A list of modern dependencies with version numbers\n")
                f.write("6. Instructions for running and testing the application\n")
                f.write("\n")
                
                f.write("## Final Notes\n")
                f.write("Focus on creating a secure, maintainable version of this software. Document any deviations "
                        "from the original implementation and explain your reasoning. If certain components cannot "
                        "be reproduced due to missing information, note this and provide placeholder implementations "
                        "with TODO comments for future completion.\n")
            
            logger.info(f"Generated reconstruction prompt for {project_name} at {prompt_path}")
            return str(prompt_path)
        except Exception as e:
            logger.error(f"Error generating prompt for {project_name}: {str(e)}")
            return None
