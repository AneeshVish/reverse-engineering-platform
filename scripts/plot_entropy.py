import argparse
import matplotlib.pyplot as plt
import math


def file_entropy(path, blocksize=4096):
    """Calculate the Shannon entropy of a file."""
    entropies = []
    try:
        with open(path, 'rb') as f:
            while True:
                data = f.read(blocksize)
                if not data:
                    break
                freq = [0] * 256
                for b in data:
                    freq[b] += 1
                entropy = 0.0
                for count in freq:
                    if count == 0:
                        continue
                    p = count / len(data)
                    entropy -= p * math.log2(p)
                entropies.append(entropy)
    except Exception:
        pass
    return entropies


def main():
    parser = argparse.ArgumentParser(description="Plot file entropy by block.")
    parser.add_argument('file', help="File to analyze")
    args = parser.parse_args()
    entropies = file_entropy(args.file)
    plt.plot(entropies)
    plt.title(f"Entropy plot: {args.file}")
    plt.xlabel("Block number")
    plt.ylabel("Entropy (bits)")
    plt.show()

if __name__ == "__main__":
    main()
