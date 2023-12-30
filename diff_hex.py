#!/usr/bin/env python3

import sys


def main():
    hex_strings = []

    # Check if input is being piped
    if not sys.stdin.isatty():
        for line in sys.stdin:
            hex_strings.append(line.strip())

    # Check if a file flag is provided
    elif len(sys.argv) == 3 and (sys.argv[1] == "--file" or sys.argv[1] == "-f"):
        try:
            with open(sys.argv[2], "r") as file:
                hex_strings = [line.strip() for line in file]
        except IOError as e:
            print(f"Error reading file: {e}")
            sys.exit(1)

    # Otherwise, treat arguments as hex strings
    else:
        hex_strings = sys.argv[1:]

    # Check if hex strings are provided
    if not hex_strings:
        print("Usage: python script_name.py hex_string1 hex_string2 [hex_string3 ...]")
        print("       cat hex_strings.txt | python script_name.py")
        print("       python script_name.py --file path/to/hex_strings.txt")
        sys.exit(1)

    # Call the function and print the result
    result = compare_hex_strings(hex_strings)
    print(result)


def compare_hex_strings(hex_strings):
    # Split each hex string into chunks of two characters
    split_hex = [list(map("".join, zip(*[iter(s)] * 2))) for s in hex_strings]

    # Transpose the list to compare byte by byte
    transposed_hex = list(zip(*split_hex))

    # Replace differing bytes with wildcards
    result = []
    for byte_group in transposed_hex:
        if all(byte == byte_group[0] for byte in byte_group):
            result.append(byte_group[0])
        else:
            result.append("..")

    return "".join(result)


if __name__ == "__main__":
    main()
