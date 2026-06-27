import logging
import lief
import mimetypes
from pathlib import Path
from enum import Enum
import gc
from src.core.novel_binary_parser import NovelBinaryParser

class FileType(Enum):
    PE = 1
    ELF = 2
    MACHO = 3
    PYTHON = 4
    JAVA = 5
    WASM = 6
    RAW = 7

class UniversalLoader:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.file_type = None
        self.raw_data = None
        self.parsed = None

    def get_section_content(self, section_name):
        """
        Extract section content by name for PE/ELF/MACHO binaries.
        Returns bytes or None.
        """
        if self.parsed is None:
            self.logger.error(f"No parsed binary loaded.")
            return None
        try:
            # LIEF section extraction
            if hasattr(self.parsed, 'sections'):
                for section in getattr(self.parsed, 'sections', []):
                    if getattr(section, 'name', None) == section_name:
                        if hasattr(section, 'content'):
                            # LIEF returns list of ints, convert to bytes
                            return bytes(section.content)
                        elif hasattr(section, 'get_data'):
                            return section.get_data()
                        else:
                            self.logger.error(f"Section {section_name} has no content attribute.")
                            return None
            self.logger.error(f"Section {section_name} not found in binary.")
            return None
        except Exception as e:
            self.logger.error(f"Error extracting section {section_name}: {e}")
            return None

    def load(self, file_path):
        path = Path(file_path)
        if not path.exists():
            self.logger.error("File not found")
            return False
        if path.is_dir():
            # A directory (e.g. a macOS .app bundle) is not a single binary.
            self.logger.error(f"Path is a directory, not a binary: {file_path}")
            self.file_type = FileType.RAW
            self.parsed = None
            self.raw_data = None
            return False
        try:
            with open(path, 'rb') as f:
                try:
                    self.raw_data = f.read()
                except (UnicodeDecodeError, IOError) as e:
                    self.logger.error(f"[UniversalLoader] File read error: {e}")
                    self.raw_data = None
        except Exception as e:
            self.logger.error(f"Failed to read file: {e}")
            self.file_type = FileType.RAW
            self.raw_data = None
            self.parsed = None
            return True

        # --- Novel detection/classification step ---
        parser = NovelBinaryParser()
        info = parser.detect_format(self.raw_data)
        self.logger.info(f"[NovelBinaryParser] Type: {info['type']}, Confidence: {info['confidence']}, Rationale: {info['rationale']}, Entropy: {info['entropy']}")
        self.file_type = getattr(FileType, info['type'], FileType.RAW) if info['type'] in FileType.__members__ else FileType.RAW
        self.novel_detection_info = info
        # Optionally, parse sections and expose them
        self.novel_sections = parser.parse_sections(self.raw_data, info['type'])

        # Only use LIEF for deep parsing if detection is confident
        if info['confidence'] > 0.7 and info['type'] in ['PE', 'ELF', 'MACHO']:
            try:
                self.parsed = lief.parse(str(path))
            except Exception as e:
                self.logger.error(f"LIEF parse failed: {e}")
                self.parsed = None
        else:
            self.parsed = None  # Not a known format or not confident

        # Handle other formats as before
        if self.file_type == FileType.PYTHON and path.suffix == '.pyc':
            try:
                from src.core.python_decompiler import PythonDecompiler
                self.parsed = PythonDecompiler().decompile(path)
            except Exception as e:
                self.logger.error(f"Python decompilation failed: {e}")
                self.parsed = None
        elif self.file_type == FileType.JAVA and path.suffix in ['.class', '.jar']:
            self.parsed = None  # Optionally add Java decompilation
        elif self.file_type == FileType.WASM and path.suffix == '.wasm':
            self.parsed = None  # Optionally add WASM decompilation
        elif self.file_type == FileType.RAW and path.suffix == '.bin':
            self.parsed = None
        return True


    def cleanup(self):
        """Explicitly release LIEF objects and force garbage collection."""
        self.parsed = None
        self.raw_data = None
        gc.collect()
