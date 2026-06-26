import logging
from uncompyle6.main import decompile_file
from io import StringIO

class PythonDecompiler:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def decompile(self, pyc_path):
        try:
            output = StringIO()
            decompile_file(str(pyc_path), output)
            return output.getvalue()
        except Exception as e:
            self.logger.error(f"Decompilation failed: {e}")
            return ""
