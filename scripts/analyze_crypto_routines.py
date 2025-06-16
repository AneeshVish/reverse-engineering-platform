import os
import argparse
import pefile
import re
from capstone import *
from capstone.x86 import *
from pathlib import Path

# Patterns for common Windows crypto APIs
CRYPTO_PATTERNS = [
    b'CryptEncrypt', b'CryptDecrypt', b'CryptAcquireContext', b'CryptGenKey', b'CryptImportKey',
    b'CryptExportKey', b'CryptCreateHash', b'CryptHashData', b'CryptDeriveKey',
    b'BCryptEncrypt', b'BCryptDecrypt', b'BCryptGenRandom', b'BCryptHashData',
    b'AES', b'DES', b'RC4', b'RSA', b'SHA', b'MD5', b'Blowfish', b'ChaCha', b'Poly1305'
]


def scan_binary_for_crypto_apis(binary_path):
    """Scan a PE binary for crypto API usage."""
    try:
        pe = pefile.PE(binary_path)
        apis = set()
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        for pat in CRYPTO_PATTERNS:
                            if pat.lower() in imp.name.lower():
                                apis.add(imp.name.decode())
        return list(apis)
    except Exception as e:
        return [f"[ERROR] {e}"]


def disassemble_sections(binary_path):
    """Disassemble .text section and look for crypto patterns in instructions."""
    try:
        pe = pefile.PE(binary_path)
        text_section = None
        for section in pe.sections:
            if b'.text' in section.Name:
                text_section = section
                break
        if not text_section:
            return []
        code = text_section.get_data()
        base = pe.OPTIONAL_HEADER.ImageBase + text_section.VirtualAddress
        md = Cs(CS_ARCH_X86, CS_MODE_32 if pe.FILE_HEADER.Machine == 0x14c else CS_MODE_64)
        md.detail = True
        routines = []
        for insn in md.disasm(code, base):
            if insn.mnemonic in ['call', 'jmp']:
                if any(pat.lower() in insn.op_str.lower().encode() for pat in CRYPTO_PATTERNS):
                    routines.append({
                        'address': hex(insn.address),
                        'mnemonic': insn.mnemonic,
                        'op_str': insn.op_str
                    })
        return routines
    except Exception as e:
        return [f"[ERROR] {e}"]


def main():
    parser = argparse.ArgumentParser(description="Analyze PE binary for crypto API usage and routines.")
    parser.add_argument('binary', help="Path to PE binary (.exe, .dll)")
    args = parser.parse_args()
    
    print(f"[INFO] Scanning {args.binary} for crypto APIs...")
    apis = scan_binary_for_crypto_apis(args.binary)
    print(f"Crypto APIs found: {apis}")
    
    print(f"[INFO] Disassembling and scanning for crypto routines...")
    routines = disassemble_sections(args.binary)
    print(f"Crypto-related routines: {routines}")

if __name__ == "__main__":
    main()
