import os
import math
import argparse
import json
from pathlib import Path

# Common encrypted file extensions (expand as needed)
ENCRYPTED_EXTENSIONS = [
    '.enc', '.encrypted', '.aes', '.crypt', '.cry', '.locked', '.vault', '.bin', '.dat', '.lock', '.crypt12', '.cry', '.enc1', '.enc2', '.enc3'
]

ENTROPY_THRESHOLD = 7.5  # Files above this are likely encrypted/compressed


def file_entropy(path, blocksize=4096):
    """Calculate the Shannon entropy of a file."""
    try:
        with open(path, 'rb') as f:
            data = f.read(blocksize)
            if not data:
                return 0.0
            freq = [0] * 256
            for b in data:
                freq[b] += 1
            entropy = 0.0
            for count in freq:
                if count == 0:
                    continue
                p = count / len(data)
                entropy -= p * math.log2(p)
            return entropy
    except Exception:
        return 0.0


def scan_directory(root_dir, min_size=1024, entropy_threshold=ENTROPY_THRESHOLD):
    """Scan directory for potentially encrypted files."""
    results = []
    for dirpath, _, filenames in os.walk(root_dir):
        for fname in filenames:
            fpath = os.path.join(dirpath, fname)
            try:
                size = os.path.getsize(fpath)
                ext = Path(fname).suffix.lower()
                entropy = file_entropy(fpath)
                encrypted_ext = ext in ENCRYPTED_EXTENSIONS
                suspicious = encrypted_ext or (size > min_size and entropy >= entropy_threshold)
                if suspicious:
                    results.append({
                        'file': fpath,
                        'size': size,
                        'entropy': entropy,
                        'extension': ext,
                        'encrypted_ext': encrypted_ext
                    })
            except Exception:
                continue
    return results


def main():
    parser = argparse.ArgumentParser(description="Scan for potentially encrypted files.")
    parser.add_argument('directory', help="Directory to scan")
    parser.add_argument('--output', '-o', help="Output JSON file", default="encrypted_files_report.json")
    parser.add_argument('--min-size', type=int, default=1024, help="Minimum file size to scan (bytes)")
    parser.add_argument('--entropy-threshold', type=float, default=ENTROPY_THRESHOLD, help="Entropy threshold")
    args = parser.parse_args()

    results = scan_directory(args.directory, min_size=args.min_size, entropy_threshold=args.entropy_threshold)
    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2)
    print(f"Scan complete. {len(results)} potentially encrypted files found. Report saved to {args.output}")

if __name__ == "__main__":
    main()
