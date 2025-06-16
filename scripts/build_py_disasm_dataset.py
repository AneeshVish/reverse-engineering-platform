import os
import ast
import dis
import json
from pathlib import Path
from typing import List, Dict

DATASET_PATH = "../dataset/py_disasm_dataset.jsonl"
PYTHON_ROOT = "../src"  # Adjust as needed to cover your codebase


def extract_functions_from_file(py_file: str) -> List[Dict]:
    """Extract all top-level functions and methods from a Python file."""
    with open(py_file, 'r', encoding='utf-8', errors='replace') as f:
        source = f.read()
    try:
        tree = ast.parse(source, filename=py_file)
    except Exception:
        return []
    functions = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            start = node.lineno - 1
            end = node.end_lineno if hasattr(node, 'end_lineno') else node.lineno
            func_src = "\n".join(source.splitlines()[start:end])
            functions.append({
                "name": node.name,
                "source": func_src
            })
    return functions


def disassemble_python_code(src: str) -> str:
    """Compile and disassemble Python code, return as string."""
    try:
        code = compile(src, '<string>', 'exec')
        instructions = []
        for instr in dis.get_instructions(code):
            instructions.append(f"{instr.opname} {instr.argrepr}")
        return "\n".join(instructions)
    except Exception:
        return ""


def find_python_files(root: str) -> List[str]:
    """Recursively find all .py files under root."""
    py_files = []
    for dirpath, _, filenames in os.walk(root):
        for fname in filenames:
            if fname.endswith('.py') and not fname.startswith('__init__'):
                py_files.append(os.path.join(dirpath, fname))
    return py_files


def build_dataset(py_root: str, out_path: str):
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    py_files = find_python_files(py_root)
    count = 0
    with open(out_path, 'w', encoding='utf-8') as out:
        for py_file in py_files:
            for func in extract_functions_from_file(py_file):
                disasm = disassemble_python_code(func['source'])
                if disasm.strip():
                    record = {
                        "assembly": disasm,
                        "python": func['source'],
                        "file": py_file,
                        "function": func['name']
                    }
                    out.write(json.dumps(record, ensure_ascii=False) + "\n")
                    count += 1
    print(f"Dataset written to {out_path} with {count} function pairs.")


if __name__ == "__main__":
    build_dataset(PYTHON_ROOT, DATASET_PATH)
