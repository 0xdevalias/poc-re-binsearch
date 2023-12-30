#!/usr/bin/env python3

import sys


def main():
    if len(sys.argv) != 3:
        print("Usage: python find_bytes.py path/to/binary 'byte_sequence'")
        sys.exit(1)

    file_path = sys.argv[1]
    byte_sequence = bytes.fromhex(sys.argv[2].replace("\\x", ""))

    with open(file_path, "rb") as file:
        data = file.read()

    idx = 0
    while idx < len(data):
        idx = data.find(byte_sequence, idx)
        if idx == -1:
            break
        print(f"0x{idx:02x}")
        idx += len(byte_sequence)


if __name__ == "__main__":
    main()
