# -*- coding: utf-8 -*-

import logging
import lief
from enum import Enum
from pathlib import Path
logger = logging.getLogger(__name__)

class BinaryType(Enum):
    UNKNOWN = 0
    ELF = 1
    PE = 2
    MACHO = 3

class BinaryLoader:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.binary = None
        self.binary_info = {}
        self.binary_type = BinaryType.UNKNOWN
        self.path = None
    
    def load(self, file_path):
        self.path = Path(file_path)
        if not self.path.exists():
            self.logger.error(f"File not found: {file_path}")
            return False
        
        try:
            self.binary = lief.parse(str(self.path))
            
            if isinstance(self.binary, lief.ELF.Binary):
                self.binary_type = BinaryType.ELF
                self._parse_elf()
            elif isinstance(self.binary, lief.PE.Binary):
                self.binary_type = BinaryType.PE
                self._parse_pe()
            elif isinstance(self.binary, lief.MachO.Binary):
                self.binary_type = BinaryType.MACHO
                self._parse_macho()
            else:
                self.logger.warning(f"Unknown binary format: {file_path}")
                return False
                
            self.logger.info(f"Successfully loaded binary: {file_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error loading binary: {e}")
            return False
    
    def _parse_elf(self):
        """Parse ELF-specific information"""
        self.binary_info = {
            'type': 'ELF',
            'machine': str(self.binary.header.machine_type),
            'entry_point': self.binary.header.entrypoint,
            'sections': [{
                'name': s.name,
                'size': s.size,
                'virtual_address': s.virtual_address
            } for s in self.binary.sections]
        }
    
    def _parse_pe(self):
        """Parse PE-specific information"""
        self.binary_info = {
            'type': 'PE',
            'machine': str(self.binary.header.machine),
            'entry_point': self.binary.optional_header.addressof_entrypoint,
            'sections': [{
                'name': s.name,
                'size': s.size,
                'virtual_address': s.virtual_address
            } for s in self.binary.sections]
        }
    
    def _parse_macho(self):
        """Parse Mach-O-specific information"""
        self.binary_info = {
            'type': 'Mach-O',
            'machine': str(self.binary.header.cpu_type),
            'entry_point': self.binary.entrypoint
        }
    
    def get_section_content(self, section_name):
        """Get the content of a section with robust PE handling"""
        if not self.binary:
            return None
        
        try:
            section = self.binary.get_section(section_name)
            if not section:
                self.logger.error(f"Section {section_name} not found")
                return None
                
            if self.binary_type == BinaryType.PE:
                # Try multiple methods for PE files
                try:
                    # Method 1: get_content()
                    content = section.get_content()
                    if content:
                        logger.debug(f"[DEBUG] PE section content retrieved via get_content(): {len(content)} bytes")
                        return bytes(content)
                except Exception as e:
                    logger.error(f"[DEBUG] get_content() failed: {e}")
                try:
                    # Method 2: Direct content access
                    if hasattr(section, 'content') and section.content:
                        logger.debug(f"[DEBUG] PE section content retrieved via .content: {len(section.content)} bytes")
                        return bytes(section.content)
                except Exception as e:
                    logger.error(f"[DEBUG] Direct content access failed: {e}")
            else:
                # ELF/Mach-O handling
                if section.content:
                    logger.debug(f"[DEBUG] Non-PE section content: {len(section.content)} bytes")
                    return section.content
                    
        except Exception as e:
            self.logger.error(f"Error getting section content: {e}")
            logger.error(f"[DEBUG] Section content retrieval failed: {e}")
        return None
    
    def get_binary_info(self):
        """Get the parsed binary information"""
        return self.binary_info
    
    def cleanup(self):
        """Explicitly release LIEF objects and force garbage collection."""
        self.binary = None
        self.binary_info = {}
        import gc
        gc.collect()

    def get_sections(self):
        """Get the sections from the binary"""
        return self.binary.sections if self.binary else []