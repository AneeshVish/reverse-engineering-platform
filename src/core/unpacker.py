import subprocess
import logging
import tempfile
import os

class BasicUnpacker:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def unpack(self, binary_path, output_path=None):
        """
        Try to unpack a binary using UPX.
        Returns the path to the unpacked binary, or None if not applicable.
        """
        # Only try to unpack files that are likely to be packed binaries
        valid_exts = ['.exe', '.dll', '.bin', '.so', '.elf', '.macho', '.pyc', '.jar', '.class', '.wasm']
        ext = os.path.splitext(binary_path)[1].lower()
        if ext not in valid_exts:
            self.logger.info(f"Skipping UPX unpack for non-binary file: {binary_path}")
            return None
        if output_path is None:
            output_path = tempfile.mktemp(suffix=".unpacked")
        try:
            # Always use encoding utf-8 and errors replace for robust Windows compatibility
            result = subprocess.run([
                "upx", "-d", binary_path, "-o", output_path
            ], encoding='utf-8', errors='replace', capture_output=True)
            if result.returncode == 0:
                self.logger.info(f"Unpacked to {output_path}")
                return output_path
            elif result.returncode == 2 and 'NotPackedException' in result.stdout + result.stderr:
                self.logger.info(f"UPX: {binary_path} is not packed (NotPackedException)")
                return None
            elif 'file is too small' in result.stdout + result.stderr:
                self.logger.info(f"UPX: {binary_path} is too small to unpack. Skipping.")
                return None
            elif 'CantUnpackException' in result.stdout + result.stderr or 'not yet supported' in result.stdout + result.stderr:
                self.logger.info(f"UPX: {binary_path} is not supported for unpacking (architecture not supported by UPX). Skipping.")
                return None
            else:
                self.logger.error(f"UPX failed for {binary_path}: {result.stderr}")
                return None
        except FileNotFoundError as e:
            self.logger.error(f"UPX not found: {e}")
            return None
