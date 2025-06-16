import argparse
import sys
import os
import itertools
from base64 import b64decode
from binascii import unhexlify
from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import unpad

def try_decrypt(ciphertext, key, algo, iv=None):
    try:
        if algo == 'aes':
            cipher = AES.new(key, AES.MODE_CBC, iv) if iv else AES.new(key, AES.MODE_ECB)
        elif algo == 'des':
            cipher = DES.new(key, DES.MODE_CBC, iv) if iv else DES.new(key, DES.MODE_ECB)
        else:
            return False, None
        pt = cipher.decrypt(ciphertext)
        # Try to unpad, if fails, likely wrong key
        try:
            pt = unpad(pt, AES.block_size if algo == 'aes' else DES.block_size)
        except Exception:
            return False, None
        # Heuristic: check if plaintext is mostly printable
        if sum(32 <= b <= 126 for b in pt) / len(pt) > 0.85:
            return True, pt
    except Exception:
        pass
    return False, None

def brute_force(ciphertext, algo, key_length, charset, iv=None, max_attempts=1000000):
    attempts = 0
    for key_tuple in itertools.product(charset, repeat=key_length):
        key_bytes = bytes(''.join(key_tuple), 'utf-8')
        # Pad/trim key to required length
        if algo == 'aes':
            key_bytes = key_bytes.ljust(16, b'\0')[:16]
        elif algo == 'des':
            key_bytes = key_bytes.ljust(8, b'\0')[:8]
        ok, pt = try_decrypt(ciphertext, key_bytes, algo, iv)
        attempts += 1
        if ok:
            return ''.join(key_tuple), pt, attempts
        if attempts >= max_attempts:
            break
    return None, None, attempts

def main():
    parser = argparse.ArgumentParser(description="Brute force attack on AES/DES encrypted files.")
    parser.add_argument('encrypted_file', help="Path to encrypted file")
    parser.add_argument('--algo', choices=['aes', 'des'], default='aes', help="Algorithm")
    parser.add_argument('--keylen', type=int, default=4, help="Key length (characters)")
    parser.add_argument('--charset', default='0123456789abcdef', help="Charset for brute force (default: hex)")
    parser.add_argument('--iv', help="IV (hex/base64, optional)")
    parser.add_argument('--max', type=int, default=1000000, help="Max attempts (default 1M)")
    args = parser.parse_args()

    with open(args.encrypted_file, 'rb') as f:
        ciphertext = f.read()
    iv = None
    if args.iv:
        try:
            iv = unhexlify(args.iv)
        except Exception:
            try:
                iv = b64decode(args.iv)
            except Exception:
                print("[!] Could not decode IV.", file=sys.stderr)
                sys.exit(1)
    key, pt, attempts = brute_force(ciphertext, args.algo, args.keylen, args.charset, iv, args.max)
    if key:
        print(f"[+] Key found after {attempts} attempts: {key}")
        print(pt.decode(errors='replace'))
    else:
        print(f"[-] No key found after {attempts} attempts.")

if __name__ == "__main__":
    main()
