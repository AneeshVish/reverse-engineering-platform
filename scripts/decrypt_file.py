import argparse
from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import unpad
import base64

ALGOS = {
    'aes': AES,
    'des': DES
}


def decrypt_file(input_path, output_path, key, algo='aes', iv=None):
    with open(input_path, 'rb') as f:
        ciphertext = f.read()
    cipher = ALGOS[algo.lower()].new(key, ALGOS[algo.lower()].MODE_CBC, iv) if iv else ALGOS[algo.lower()].new(key, ALGOS[algo.lower()].MODE_ECB)
    plaintext = unpad(cipher.decrypt(ciphertext), ALGOS[algo.lower()].block_size)
    with open(output_path, 'wb') as f:
        f.write(plaintext)
    print(f"Decryption complete. Output written to {output_path}")


def main():
    parser = argparse.ArgumentParser(description="Decrypt a file with a given key.")
    parser.add_argument('input', help="Encrypted file path")
    parser.add_argument('output', help="Decrypted output file path")
    parser.add_argument('key', help="Decryption key (hex or base64)")
    parser.add_argument('--algo', choices=['aes', 'des'], default='aes')
    parser.add_argument('--iv', help="IV (hex or base64, optional)")
    args = parser.parse_args()

    # Parse key and IV
    try:
        if len(args.key) in (32, 64):
            key = bytes.fromhex(args.key)
        else:
            key = base64.b64decode(args.key)
        iv = bytes.fromhex(args.iv) if args.iv else None
    except Exception:
        print("[ERROR] Invalid key or IV format.")
        return
    decrypt_file(args.input, args.output, key, algo=args.algo, iv=iv)

if __name__ == "__main__":
    main()
