#!/usr/bin/env python3

import sys

def main():
    # Check for the correct number of arguments
    if len(sys.argv) < 2:
        print("Usage: python diff_hex.py hex_string1 hex_string2 [hex_string3 ...]")
        sys.exit(1)

    # Get hex strings from command line arguments
    hex_strings = sys.argv[1:]

    # Call the function and print the result
    result = compare_hex_strings(hex_strings)
    print(result)

def compare_hex_strings(hex_strings):
    # Split each hex string into chunks of two characters
    split_hex = [list(map(''.join, zip(*[iter(s)]*2))) for s in hex_strings]

    # Transpose the list to compare byte by byte
    transposed_hex = list(zip(*split_hex))

    # Replace differing bytes with wildcards
    result = []
    for byte_group in transposed_hex:
        if all(byte == byte_group[0] for byte in byte_group):
            result.append(byte_group[0])
        else:
            result.append('..')

    return ''.join(result)

if __name__ == "__main__":
    main()
