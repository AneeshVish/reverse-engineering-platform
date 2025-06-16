import argparse
from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import unpad
import base64
import os

ALGOS = {'aes': AES, 'des': DES}


def try_decrypt(ciphertext, key, algo='aes', iv=None):
    try:
        cipher = ALGOS[algo.lower()].new(key, ALGOS[algo.lower()].MODE_CBC, iv) if iv else ALGOS[algo.lower()].new(key, ALGOS[algo.lower()].MODE_ECB)
        plaintext = unpad(cipher.decrypt(ciphertext), ALGOS[algo.lower()].block_size)
        return plaintext
    except Exception:
        return None


def main():
    parser = argparse.ArgumentParser(description="Dictionary attack for encrypted files.")
    parser.add_argument('input', help="Encrypted file path")
    parser.add_argument('wordlist', help="Wordlist file (hex or base64 keys, one per line)")
    parser.add_argument('--algo', choices=['aes', 'des'], default='aes')
    parser.add_argument('--iv', help="IV (hex or base64, optional)")
    parser.add_argument('--output', help="Output file for successful decryption (optional)")
    args = parser.parse_args()

    with open(args.input, 'rb') as f:
        ciphertext = f.read()
    iv = bytes.fromhex(args.iv) if args.iv else None
    with open(args.wordlist, 'r') as f:
        for line in f:
            key_str = line.strip()
            if not key_str:
                continue
            try:
                key = bytes.fromhex(key_str) if all(c in '0123456789abcdefABCDEF' for c in key_str) else base64.b64decode(key_str)
            except Exception:
                continue
            pt = try_decrypt(ciphertext, key, algo=args.algo, iv=iv)
            if pt:
                print(f"[SUCCESS] Key: {key_str}")
                if args.output:
                    with open(args.output, 'wb') as out:
                        out.write(pt)
                break
        else:
            print("[FAIL] No valid key found in wordlist.")

if __name__ == "__main__":
    main()
