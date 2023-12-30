#!/usr/bin/env python3

import argparse
import sys
import re
import textwrap


def parse_arguments():
    parser = argparse.ArgumentParser(
        prog="diff_hex.py",
        description="Generate a pattern mask from multiple hex strings",
        allow_abbrev=False,
    )

    parser.add_argument(
        "--relaxed",
        action="store_true",
        help="Disable strict input validation checks (eg. on hex string length and characters)",
    )

    inputs_group = parser.add_argument_group(
        "inputs",
        "Choose one of the following methods to specify the input hex strings to be processed.",
    )

    # Only allow --file or hex_strings, not both
    mutex_group = inputs_group.add_mutually_exclusive_group(required=True)
    # The default=[] is required here to allow nargs="*" to work with mutually exclusive groups
    #   See: https://github.com/python/cpython/issues/86020#issuecomment-1093884766
    mutex_group.add_argument(
        "hex_strings",
        nargs="*",
        default=[],
        help="Hex strings to be compared (or '-' for STDIN)",
    )
    mutex_group.add_argument(
        "--file",
        "-f",
        type=argparse.FileType("r"),
        help="File containing hex strings to be compared (or '-' for STDIN)",
    )

    args = parser.parse_args()

    # Syntactic sugar / shortcut for reading from STDIN
    if len(args.hex_strings) == 1 and args.hex_strings[0] == "-":
        args.file = sys.stdin
        args.hex_strings = []

    # Warn if STDIN seems to have input, but --file is not specified
    if not sys.stdin.isatty() and not args.file:
        print(
            "Warning: STDIN input detected but '--file -' not specified. "
            "STDIN will be ignored. Use '--file -' for STDIN input.",
            file=sys.stderr,
        )

    # Determine the source of the hex strings
    source = args.file if args.file else args.hex_strings

    # Process the source
    hex_strings = [
        trimmed_line
        for line in source
        if (trimmed_line := line.strip()) and not trimmed_line.startswith("#")
    ]

    # Check if at least two hex strings are provided
    if len(hex_strings) < 2:
        parser.error("At least two hex strings are required for comparison.")

    if not args.relaxed:
        # Validate the format of the provided hex strings
        invalid_hex_strings = [
            s for s in hex_strings if not re.fullmatch(r"([0-9a-fA-F]{2})+", s)
        ]
        if invalid_hex_strings:
            # invalid_strs = "\n".join("  " + s for s in invalid_hex_strings)
            invalid_strs = textwrap.indent("\n".join(invalid_hex_strings), "  ")
            error_message = f"""
            All hex strings must be of even length and contain only valid hexadecimal characters (0-9a-fA-F).
            
            Invalid hex strings:
            {invalid_strs}
            
            If you know what you're doing and you need to disable this check, use the --relaxed flag.
            """
            parser.error(
                textwrap.indent(textwrap.dedent(error_message.rstrip()), prefix="  ")
            )

    return hex_strings


def main():
    hex_strings = parse_arguments()

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
