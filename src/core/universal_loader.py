import logging
import lief
import mimetypes
from pathlib import Path
from enum import Enum

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
        
        try:
            with open(path, 'rb') as f:
                try:
                    self.raw_data = f.read()
                except (UnicodeDecodeError, IOError) as e:
                    logging.error(f"[UniversalLoader] File read error: {e}")
                    self.raw_data = None
        except Exception as e:
            self.logger.error(f"Failed to read file: {e}")
            self.file_type = FileType.RAW
            self.raw_data = None
            self.parsed = None
            return True
        
        # Try to detect MIME type using mimetypes and fallback to extension
        mime = ''
        try:
            mime, _ = mimetypes.guess_type(str(path))
            if not mime:
                if self.raw_data is not None:
                    # fallback: check for PE/ELF/MACHO signatures
                    if isinstance(self.raw_data, (bytes, bytearray)):
                        if len(self.raw_data) >= 2 and self.raw_data[:2] == b'MZ':
                            mime = 'application/x-dosexec'
                        elif len(self.raw_data) >= 4 and self.raw_data[:4] == b'\x7fELF':
                            mime = 'application/x-elf'
                        elif len(self.raw_data) >= 4 and self.raw_data[:4] in [b'\xcf\xfa\xed\xfe', b'\xfe\xed\xfa\xcf']:
                            mime = 'application/x-mach-binary'
                        else:
                            self.logger.debug(f"raw_data does not match known binary signatures for {file_path}")
                    else:
                        self.logger.warning(f"raw_data is not bytes for {file_path}, type={type(self.raw_data)}")
                else:
                    self.logger.warning(f"raw_data is None when checking signatures for {file_path}")
        except Exception as e:
            self.logger.error(f"Failed to detect mime type: {e}")
            mime = ''
        
        try:
            # Defensive: ensure suffix is str and not None
            suffix = path.suffix.lower() if path.suffix else ''
            # Detect file type
            if (mime and ('PE32' in mime or 'PE64' in mime)) or suffix in ['.exe', '.dll']:
                self.file_type = FileType.PE
                try:
                    self.parsed = lief.parse(str(path))
                except Exception as e:
                    self.logger.error(f"LIEF PE parse failed: {e}")
                    self.parsed = None
            elif (mime and 'ELF' in mime) or suffix in ['.so']:
                self.file_type = FileType.ELF
                try:
                    self.parsed = lief.parse(str(path))
                except Exception as e:
                    self.logger.error(f"LIEF ELF parse failed: {e}")
                    self.parsed = None
            elif (mime and 'Mach-O' in mime) or suffix in ['.dylib', '.macho']:
                self.file_type = FileType.MACHO
                try:
                    self.parsed = lief.parse(str(path))
                except Exception as e:
                    self.logger.error(f"LIEF Mach-O parse failed: {e}")
                    self.parsed = None
            elif suffix == '.pyc':
                self.file_type = FileType.PYTHON
                try:
                    from src.core.python_decompiler import PythonDecompiler
                    self.parsed = PythonDecompiler().decompile(path)
                except Exception as e:
                    self.logger.error(f"Python decompilation failed: {e}")
                    self.parsed = None
            elif suffix in ['.class', '.jar']:
                self.file_type = FileType.JAVA
                self.parsed = None  # Optionally add Java decompilation
            elif suffix == '.wasm':
                self.file_type = FileType.WASM
                self.parsed = None  # Optionally add WASM decompilation
            elif suffix == '.bin':
                # Accept .bin files as raw binaries
                self.file_type = FileType.RAW
                self.parsed = None
            else:
                self.file_type = FileType.RAW
                self.parsed = None
        except Exception as e:
            self.logger.error(f"UniversalLoader failed to parse file: {e} (type: {type(e)})")
            self.file_type = FileType.RAW
            self.parsed = None
        
        return True
