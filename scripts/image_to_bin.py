import sys
import os


def image_to_bin(image_path):
    if not os.path.isfile(image_path):
        print(f"[ERROR] File not found: {image_path}")
        return
    base, ext = os.path.splitext(image_path)
    ext = ext.lstrip('.')
    bin_path = f"{base}_{ext}.bin"
    try:
        with open(image_path, 'rb') as img_file:
            data = img_file.read()
        with open(bin_path, 'wb') as bin_file:
            bin_file.write(data)
        print(f"[INFO] Binary file created: {bin_path}")
    except Exception as e:
        print(f"[ERROR] Failed to convert image: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python image_to_bin.py <image_file>")
        sys.exit(1)
    image_to_bin(sys.argv[1])
