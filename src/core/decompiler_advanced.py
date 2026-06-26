from retdec.decompiler import Decompiler
import logging
import tempfile
import os

class AdvancedDecompiler:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.decompiler = Decompiler()

    def decompile(self, binary_path, output_dir=None):
        """
        Decompile a binary using RetDec.
        Returns the path to the decompiled C source.
        """
        if output_dir is None:
            output_dir = tempfile.mkdtemp()
        output_path = os.path.join(output_dir, "output.c")
        self.logger.info(f"Decompiling {binary_path} to {output_path}")
        self.decompiler.run(binary_path, output_format="c", output_file=output_path)
        return output_path
