import argparse
import re
import os
from pathlib import Path

WEAK_ALGOS = ['des', 'rc4', 'md5', 'sha1', 'ecb']
KEYWORDS = ['key', 'password', 'secret', 'token', 'auth']


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

MIN_KEYLEN = 16
LONG_KEYLEN = 32
ENTROPY_THRESHOLD = 4.2


def analyze_file(filepath):
    findings = []
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
        text = data.decode(errors='replace')
        # Hardcoded key/secret & master key detection
        for kw in KEYWORDS:
            for m in re.finditer(rf'{kw}[^\n]{{0,40}}([A-Za-z0-9+/=]{{16,}}|0x[A-Fa-f0-9]{{16,}})', text, re.IGNORECASE):
                val = m.group(1) if m.lastindex else m.group(0)
                offset = m.start()
                label = 'master_key' if 'master' in kw.lower() or 'main' in kw.lower() or len(val) >= 32 else 'hardcoded_secret'
                findings.append({
                    'type': label,
                    'desc': f"Possible {'master key' if label == 'master_key' else 'hardcoded ' + kw} detected: {val}",
                    'location': f"offset {offset}",
                    'value': val
                })
        # Weak algorithms
        for algo in WEAK_ALGOS:
            if re.search(algo, text, re.IGNORECASE):
                findings.append({'type': 'weak_algo', 'desc': f'Use of weak algorithm: {algo.upper()}.'})
        # Insecure API usage
        if re.search(r'ECB', text):
            findings.append({'type': 'insecure_api', 'desc': 'ECB mode detected (insecure).'})
        # Short keys
        for m in re.finditer(r'([A-Fa-f0-9]{8,32})', text):
            if len(m.group()) < 16:
                findings.append({'type': 'short_key', 'desc': f'Short key found: {m.group()}.'})
        # High-entropy binary blobs (potential keys)
        for i in range(0, len(data) - MIN_KEYLEN):
            for klen in (MIN_KEYLEN, LONG_KEYLEN):
                chunk = data[i:i+klen]
                ent = entropy(chunk)
                if ent > ENTROPY_THRESHOLD:
                    findings.append({'type': 'high_entropy_key', 'desc': f'High-entropy blob at offset {i}, len={klen}, entropy={round(ent,2)}', 'hex': chunk.hex()})
        # Long keys (possible master keys)
        import hashlib
        import string
        demo_wordlist = ['password', 'secret', 'admin', 'letmein', '123456', 'masterkey', 'test']
        # Helper to filter out false positives
        def is_likely_false_positive(val):
            # Exclude all uppercase words (not hex) and known function-like names
            if val.isalpha() and val.isupper():
                return True
            # Exclude common API/function names (add more as needed)
            known_names = [
                'CONVERTSECURITYDESCRIPTORTOSTRINGSECURITYDESCRIPTORA',
                'EFTHENDEFERRABLELSEXCLUDELETEMPORARYISNULLSAVEPOINTERSECTIESNOTNULLIKEXCEPTRANSACTIONATURALTERAISEXCLUSIVEXISTSCONSTRAINTOFFSETRIGGERANGENERATEDETACHAVINGLOBEGINNEREFERENCESUNIQUERYWITHOUTERELEASEATTACHBETWEENOTHINGROUPSCASCADEFAULTCASECOLLATECREATECURRENT'
            ]
            if val.upper() in known_names:
                return True
            # Exclude if all ASCII and not hex/base64-like
            if all(c in string.ascii_letters for c in val):
                return True
            return False
        for m in re.finditer(r'([A-Fa-f0-9]{32,})', text):
            val = m.group()
            if is_likely_false_positive(val):
                continue
            offset = m.start()
            key_info = {'type': 'master_key',
                        'desc': f'Possible master key found: {val}',
                        'location': f"offset {offset}",
                        'value': val}
            # Detect hash type
            cracked = None
            hash_type = None
            if len(val) == 32:
                # Could be MD5
                hash_type = 'MD5'
                for word in demo_wordlist:
                    if hashlib.md5(word.encode()).hexdigest() == val.lower():
                        cracked = word
                        break
            elif len(val) == 40:
                # Could be SHA1
                hash_type = 'SHA1'
                for word in demo_wordlist:
                    if hashlib.sha1(word.encode()).hexdigest() == val.lower():
                        cracked = word
                        break
            elif len(val) == 64:
                # Could be SHA256
                hash_type = 'SHA256'
                for word in demo_wordlist:
                    if hashlib.sha256(word.encode()).hexdigest() == val.lower():
                        cracked = word
                        break
            if hash_type:
                key_info['desc'] += f" (detected as {hash_type} hash)"
                if cracked:
                    key_info['desc'] += f" [plaintext: '{cracked}']"
                else:
                    key_info['desc'] += " [could not recover plaintext]"
            # Try simple AES decryption if length matches
            elif len(val) in (32, 48, 64):
                try:
                    from Crypto.Cipher import AES
                    import binascii
                    key_bytes = bytes.fromhex(val)
                    demo_aes_keys = [b'0123456789abcdef', b'password12345678', b'masterkeymasterk']
                    for demo_key in demo_aes_keys:
                        cipher = AES.new(demo_key, AES.MODE_ECB)
                        pt = cipher.decrypt(key_bytes)
                        if all(32 <= b <= 126 for b in pt):
                            key_info['desc'] += f" (decrypted as AES: '{pt.decode(errors='replace')}')"
                            break
                except Exception:
                    pass
            findings.append(key_info)
    except Exception as e:
        findings.append({'type': 'error', 'desc': str(e)})
    return findings


def scan_directory(directory):
    all_findings = {}
    for root, _, files in os.walk(directory):
        for fname in files:
            fpath = os.path.join(root, fname)
            findings = analyze_file(fpath)
            if findings:
                all_findings[fpath] = findings
    return all_findings


def main():
    parser = argparse.ArgumentParser(description="Security audit for crypto/code weaknesses.")
    parser.add_argument('target', help="File or directory to scan")
    parser.add_argument('--output', '-o', help="Output file (optional)")
    args = parser.parse_args()
    if os.path.isdir(args.target):
        findings = scan_directory(args.target)
    else:
        findings = {args.target: analyze_file(args.target)}
    for f, issues in findings.items():
        print(f"\nFile: {f}")
        for issue in issues:
            print(f"  - {issue['type']}: {issue['desc']}")
    if args.output:
        import json
        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(findings, f, indent=2)

if __name__ == "__main__":
    main()
