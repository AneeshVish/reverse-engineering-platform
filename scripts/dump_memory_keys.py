import argparse
import re
import math
from pathlib import Path

KEY_PATTERNS = [
    b'key', b'password', b'secret', b'token', b'auth'
]

ENTROPY_THRESHOLD = 4.0


def entropy(data):
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


def scan_memory_dump(path, min_len=16, blocksize=4096):
    results = []
    with open(path, 'rb') as f:
        data = f.read()
    for i in range(0, len(data) - min_len):
        chunk = data[i:i+min_len]
        ent = entropy(chunk)
        if ent > ENTROPY_THRESHOLD:
            for pat in KEY_PATTERNS:
                if pat in chunk.lower():
                    results.append({'offset': i, 'pattern': pat.decode(), 'entropy': ent, 'hex': chunk.hex()})
    return results


def main():
    parser = argparse.ArgumentParser(description="Scan memory dump for key-like patterns.")
    parser.add_argument('dump', help="Memory dump file")
    parser.add_argument('--min-len', type=int, default=16, help="Minimum pattern length")
    args = parser.parse_args()
    results = scan_memory_dump(args.dump, min_len=args.min_len)
    for res in results:
        print(res)

if __name__ == "__main__":
    main()
