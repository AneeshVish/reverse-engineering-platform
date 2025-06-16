import argparse
import re
import os
from pathlib import Path

import math
KEY_PATTERNS = [
    r'([A-Za-z0-9+/=]{16,})',  # base64
    r'(0x)?[A-Fa-f0-9]{16,}',  # hex
    r'(?i)(key|password|secret|token|auth)[^\n\r\t\0]{0,40}([A-Za-z0-9+/=]{8,}|0x[A-Fa-f0-9]{8,})',
    r'([A-Za-z0-9+/=]{32,})',  # long base64
    r'(0x)?[A-Fa-f0-9]{32,}',  # long hex
    # JWT tokens
    r'([A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+)',
    # OAuth2 Bearer tokens (in text)
    r'Bearer\s+([A-Za-z0-9\-\._~\+/]+=*)',
    # Generic API/session tokens
    r'(?i)(api[_-]?key|access[_-]?token|session[_-]?token|id[_-]?token)[^\n\r\t\0]{0,40}([A-Za-z0-9\-_=\.]{16,})',
]

ENTROPY_THRESHOLD = 4.2
MIN_KEYLEN = 16
LONG_KEYLEN = 32

# Try to extract high-entropy blobs as possible keys

def entropy(data):
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    ent = 0.0
    for count in freq:
        if count == 0:
            continue
        p = count / len(data)
        ent -= p * math.log2(p)
    return ent


def scan_file_for_keys(filepath):
    results = []
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
        text = data.decode(errors='replace')
        # Regex key patterns
        for pat in KEY_PATTERNS:
            for match in re.finditer(pat, text):
                start = max(0, match.start() - 80)
                end = min(len(text), match.end() + 80)
                context = text[start:end].replace('\n', ' ')
                val = match.group(1) if match.lastindex else match.group(0)
                # Token detection
                is_token = False
                if re.fullmatch(r'[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+', val):
                    is_token = True
                if 'bearer' in pat.lower() or 'token' in pat.lower():
                    is_token = True
                if is_token:
                    results.append({
                        'file': filepath,
                        'match': val,
                        'start': match.start(),
                        'end': match.end(),
                        'type': 'token',
                        'context': context
                    })
                    continue
                # Highlight if this is a hardcoded secret
                is_secret = any(x in match.group().lower() for x in ['key', 'password', 'secret', 'token', 'auth'])
                results.append({
                    'file': filepath,
                    'match': match.group(),
                    'start': match.start(),
                    'end': match.end(),
                    'type': 'regex',
                    'context': context,
                    'hardcoded_secret': bool(is_secret)
                })
        # High-entropy binary blobs
        for i in range(0, len(data) - MIN_KEYLEN):
            for klen in (MIN_KEYLEN, LONG_KEYLEN):
                chunk = data[i:i+klen]
                ent = entropy(chunk)
                if ent > ENTROPY_THRESHOLD:
                    results.append({'file': filepath, 'offset': i, 'entropy': round(ent,2), 'hex': chunk.hex(), 'length': klen, 'type': 'high_entropy'})
    except Exception as e:
        results.append({'file': filepath, 'error': str(e)})
    return results


def scan_directory(directory):
    all_results = []
    for root, _, files in os.walk(directory):
        for fname in files:
            fpath = os.path.join(root, fname)
            all_results.extend(scan_file_for_keys(fpath))
    return all_results


def main():
    parser = argparse.ArgumentParser(description="Find likely key strings in files.")
    parser.add_argument('target', help="File or directory to scan")
    parser.add_argument('--output', '-o', help="Output file (optional)")
    args = parser.parse_args()
    if os.path.isdir(args.target):
        results = scan_directory(args.target)
    else:
        results = scan_file_for_keys(args.target)
    for res in results:
        print(res)
    if args.output:
        import json
        with open(args.output, 'w', encoding='utf-8') as f:
            import json
            json.dump(results, f, indent=2)

if __name__ == "__main__":
    main()
