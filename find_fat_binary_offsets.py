#!/usr/bin/env python3

# TODO: explore implementation that uses Python's mmap rather than reading the full binary into memory:
#   https://unix.stackexchange.com/questions/750837/searching-for-a-pattern-in-a-binary-file-using-python-script
#     https://docs.python.org/3/library/mmap.html
#        # Memory-mapped file objects behave like both bytearray and like file objects. You can use mmap objects in most places where bytearray are expected; for example, you can use the re module to search through a memory-mapped file. You can also change a single byte by doing obj[index] = 97, or change a subsequence by assigning to a slice: obj[i1:i2] = b'...'. You can also read and write data starting at the current file position, and seek() through the file to different positions.
#     https://realpython.com/python-mmap/
#       Python mmap: Improved File I/O With Memory Mapping

PROFILE = False
DEBUG = False

import argparse
import struct
import sys
import subprocess
import re

if PROFILE:
    import cProfile
    import pstats
    from pstats import SortKey

# Symbol to search for
symbol = "_IDSProtoKeyTransparencyTrustedServiceReadFrom"

# Hex strings to search for
hex_strings = {
    "x86_64": {
        "IDSProtoKeyTransparencyTrustedServiceReadFrom": "554889e54157415641554154534883ec28..89..48897dd04c8b3d",
        "NACInitAddress": "554889e541574156415541545350b87818",
        "NACKeyEstablishmentAddress": "554889e54157415641554154534881ec48010000488b05......00488b00488945d04885",
        "NACSignAddress": "554889e54157415641554154534881eca803000041",
    },
    "arm64e": {
        "IDSProtoKeyTransparencyTrustedServiceReadFrom": "7f2303d5ffc301d1fc6f01a9fa6702a9f85f03a9f65704a9f44f05a9fd7b06a9fd830191f30301aa....00..d6....f9c80280b9..6868f8....00..f7....f9..0280b9..68..f8....00..18....f9..01..eb....0054f40300aa39008052fa",
        "NACInitAddress": "7f2303d5fc6fbaa9fa6701a9f85f02a9f65703a9f44f04a9fd7b05a9fd4301910910",
        "NACKeyEstablishmentAddress": "7f2303d5ff0306d1fc6f12a9fa6713a9f85f14a9f65715a9f44f16a9fd7b17a9fdc30591....00..08....f9080140f9a883",
        "NACSignAddress": "7f2303d5fc6fbaa9fa6701a9f85f02a9f65703a9f44f04a9fd7b05a9fd430191ff4310d1fb",
    },
}

FAT_MAGIC = b"\xca\xfe\xba\xbe"  # FAT magic number in little endian
MACHO_MAGIC_32 = b"\xce\xfa\xed\xfe"  # 0xfeedface in little endian
MACHO_MAGIC_64 = b"\xcf\xfa\xed\xfe"  # 0xfeedfacf in little endian


def parse_arguments():
    parser = argparse.ArgumentParser(description="Find unique patterns in binary.")
    parser.add_argument("path", help="Path to the binary file")
    parser.add_argument(
        "--shortest-patterns",
        action="store_true",
        help="Find the shortest unique patterns for each architecture",
    )
    return parser.parse_args()


def main():
    args = parse_arguments()
    file_path = args.path
    shortest_patterns = args.shortest_patterns

    if PROFILE:
        pr = cProfile.Profile()
        pr.enable()

    architectures = scan_macho_fat_binary(file_path)
    print_arch_info(architectures)

    if shortest_patterns:
        print("\n-= Finding Shortest Unique Patterns =-")
        for i, arch in architectures.items():
            print(f"Architecture {arch['name']}:")
            arch_hex_strings = hex_strings.get(arch["name"], {})
            for name, hex_string in arch_hex_strings.items():
                shortest_pattern, offset = search_for_shortest_unique_pattern(
                    file_path, arch, hex_string
                )
                if offset is not None:
                    # print(f"  Shortest unique pattern for {name}: {shortest_pattern}, Offset: {offset}")
                    # print(f"  Shortest unique pattern for {name}: {shortest_pattern}")
                    print(f"  {name}: {shortest_pattern}")
                else:
                    # print(f"  No unique pattern found for {name}")
                    print(f"  {name}: No unique pattern found")

    print("")

    print("-= Found Symbol Offsets =-")
    for i, arch in architectures.items():
        offset = get_symbol_offset(file_path, symbol, arch["name"])
        if offset is not None:
            print(f"Offset of {symbol} in architecture {arch['name']}: {offset}")
        else:
            print(f"Symbol {symbol} not found in architecture {arch['name']}.")

    print("")

    if PROFILE:
        # search_in_architectures_with_rafind2: Approximately 16.0 times slower.
        rafind2_search_results = search_in_architectures_with_rafind2(
            file_path, architectures, hex_strings
        )
        print_search_results(
            rafind2_search_results, architectures, suffix=" (with Radare's rafind2)"
        )
        print("")

        # search_in_architectures_with_regex_on_hex_pairs: Approximately 5.95 times slower.
        search_results = search_in_architectures_with_regex_on_hex_pairs(
            file_path, architectures, hex_strings
        )
        print_search_results(
            search_results,
            architectures,
            suffix=" (with pure python regex search on hex pairs)",
        )
        print("")

        # search_in_architectures_with_regex_on_bytes: Approximately 1.42 times slower.
        search_results = search_in_architectures_with_regex_on_bytes(
            file_path, architectures, hex_strings
        )
        print_search_results(
            search_results,
            architectures,
            suffix=" (with pure python regex search on bytes)",
        )
        print("")

        # search_in_architectures_with_fixed_sequences: Approximately 1.32 times slower.
        search_results = search_in_architectures_with_fixed_sequences(
            file_path, architectures, hex_strings
        )
        print_search_results(
            search_results,
            architectures,
            suffix=" (with pure python fixed sequence search)",
        )
        print("")

    # search_in_architectures_with_fixed_sequences_and_regex: This is the fastest method.
    search_results = search_in_architectures_with_fixed_sequences_and_regex(
        file_path, architectures, hex_strings
    )
    print_search_results(
        search_results,
        architectures,
        suffix=" (with pure python fixed sequence search + regex)",
    )
    print("")

    if PROFILE:
        pr.disable()

        p = pstats.Stats(pr)
        p.strip_dirs().sort_stats(SortKey.CUMULATIVE).print_stats(
            "find_fat_binary_offsets.py"
        )


def get_arch_name(cpu_type, cpu_subtype, cpu_subtype_caps):
    """Return the human-friendly architecture name based on cpu type, subtype, and subtype capability"""
    arch_names = {
        (16777223, 3, 0): "x86_64",
        (16777228, 2, 128): "arm64e",
        # Add more architecture types if needed
    }
    return arch_names.get(
        (cpu_type, cpu_subtype, cpu_subtype_caps),
        f"Unknown (Type: {cpu_type}, Subtype: {cpu_subtype}, Subtype Capability: {cpu_subtype_caps})",
    )


def validate_macho_header(file, offset):
    """Validate the Mach-O header at the given offset"""
    original_position = file.tell()  # Remember the original position
    file.seek(offset)
    magic = file.read(4)
    file.seek(original_position)  # Reset the file position to the original
    return magic in [MACHO_MAGIC_32, MACHO_MAGIC_64]


def scan_macho_fat_binary(file_path):
    """Scan a Mach-O FAT binary and gather architecture information"""
    architectures = {}
    with open(file_path, "rb") as file:
        # Read the magic number to confirm it's a FAT binary
        magic = file.read(4)
        if magic != FAT_MAGIC:
            return "Not a FAT binary"

        # Read number of architectures
        num_archs = struct.unpack(">I", file.read(4))[0]

        # Read info for each architecture
        for i in range(num_archs):
            # Read the architecture info
            arch_info = file.read(20)
            cpu_type, cpu_subtype_full, offset, size, align = struct.unpack(
                ">IIIII", arch_info
            )

            # Extract the cpu_subtype and capability
            cpu_subtype = cpu_subtype_full & 0x00FFFFFF
            cpu_subtype_caps = (cpu_subtype_full >> 24) & 0xFF

            # Get the human-friendly architecture name
            arch_name = get_arch_name(cpu_type, cpu_subtype, cpu_subtype_caps)

            # Validate the Mach-O header
            is_valid_macho = validate_macho_header(file, offset)

            # Store architecture information
            architectures[i] = {
                "name": arch_name,
                "cpu_type": cpu_type,
                "cpu_subtype": cpu_subtype,
                "cpu_subtype_caps": cpu_subtype_caps,
                "offset": offset,
                "size": size,
                "align": align,
                "valid_macho_header": is_valid_macho,
            }

    return architectures


def print_arch_info(architectures):
    """Print information about each architecture in the FAT binary"""
    print("-= Universal Binary Sections =-")
    for i, arch in architectures.items():
        print(f"Architecture {i} ({arch['name']}):")
        print(f"  CPU Type: {arch['cpu_type']} (0x{arch['cpu_type']:x})")
        print(f"  CPU Subtype: {arch['cpu_subtype']} (0x{arch['cpu_subtype']:x})")
        print(
            f"  CPU Subtype Capability: {arch['cpu_subtype_caps']} (0x{arch['cpu_subtype_caps']:x})"
        )
        print(
            f"  Offset: 0x{arch['offset']:x} (Valid Mach-O Header: {'Yes' if arch['valid_macho_header'] else 'No'})"
        )
        print(f"  Size: {arch['size']}")
        print(f"  Align: {arch['align']}")


def get_symbol_offset(binary_path, symbol, arch):
    """Extract the offset of a named symbol for a given architecture using nm"""
    arch_flag = "--arch=x86_64" if arch == "x86_64" else "--arch=arm64e"
    try:
        # Execute nm command with the required architecture flag
        result = subprocess.check_output(
            ["/usr/bin/nm", "--defined-only", "--extern-only", arch_flag, binary_path],
            stderr=subprocess.STDOUT,
        ).decode("utf-8")

        if DEBUG:
            print(
                f"[DEBUG] get_symbol_offset bin={binary_path}, symbol={symbol}, arch={arch}"
            )

        # Parse the output to find the symbol
        for line in result.splitlines():
            if DEBUG:
                print(f"[DEBUG]   {line}")

            parts = line.split()
            if len(parts) >= 3 and parts[2] == symbol:
                # Return the offset
                return "0x" + parts[0][-6:]
    except subprocess.CalledProcessError as e:
        print(f"Error executing nm: {e.output}")
        return None

    return None


# TODO: make sure this shows 'not found' or similar if we couldn't find it?
def search_in_architectures(file_path, architectures, hex_strings):
    """Search for hex strings with placeholders in each architecture and save their offsets"""
    search_results = {}
    with open(file_path, "rb") as file:
        for i, arch in architectures.items():
            if not arch["valid_macho_header"]:
                print(
                    f"Warning: Skipping architecture {i} ({arch['name']}) due to invalid Mach-O header."
                )
                continue  # Skip if there isn't a valid Mach-O header

            file.seek(arch["offset"])
            binary_data = file.read(arch["size"])

            # Get hex strings for the current architecture
            arch_hex_strings = hex_strings.get(arch["name"], {})

            search_results[i] = {}
            for name, hex_string in arch_hex_strings.items():
                hex_string = hex_string.replace(" ", "").lower()
                hex_bytes = [
                    hex_string[i : i + 2] for i in range(0, len(hex_string), 2)
                ]

                matches = []
                for offset in range(len(binary_data) - len(hex_bytes) + 1):
                    match = True
                    for j, byte in enumerate(hex_bytes):
                        if (
                            byte != "??"
                            and byte != ".."
                            and int(byte, 16) != binary_data[offset + j]
                        ):
                            match = False
                            break
                    if match:
                        matches.append(offset)

                if matches:
                    # Store all matches
                    search_results[i][name] = matches
                    if len(matches) > 1:
                        print(
                            f"Warning: Multiple matches found for {name} in architecture {i}. Matches at offsets: {', '.join(f'0x{m:x}' for m in matches)}"
                        )

    return search_results


def find_longest_fixed_sequence(hex_pattern):
    """Finds the longest sequence of bytes in a hex pattern before the first wildcard"""
    wildcard_index = hex_pattern.find("..")
    if wildcard_index != -1:
        # Return the fixed sequence up to the wildcard
        return hex_pattern[:wildcard_index]
    else:
        # No wildcard, return the entire pattern
        return hex_pattern


def search_in_architectures_with_fixed_sequences(file_path, architectures, hex_strings):
    search_results = {}
    with open(file_path, "rb") as file:
        for i, arch in architectures.items():
            if not arch["valid_macho_header"]:
                continue

            arch_hex_strings = hex_strings.get(arch["name"], {})
            search_results[i] = {name: [] for name in arch_hex_strings}

            file.seek(arch["offset"])
            binary_data = file.read(arch["size"])

            for name, hex_string in arch_hex_strings.items():
                hex_string = hex_string.replace(" ", "").lower()
                longest_fixed = find_longest_fixed_sequence(hex_string)
                fixed_bytes = bytes.fromhex(longest_fixed)

                # Fast search for the fixed byte sequence
                start = 0
                while start < len(binary_data):
                    start = binary_data.find(fixed_bytes, start)
                    if start == -1:
                        break  # No more matches

                    # Perform detailed byte-by-byte comparison including wildcards
                    end = start + len(hex_string) // 2
                    if end <= len(binary_data):
                        hex_bytes = [
                            hex_string[j : j + 2] for j in range(0, len(hex_string), 2)
                        ]
                        if all(
                            byte == ".." or int(byte, 16) == binary_data[start + j]
                            for j, byte in enumerate(hex_bytes)
                        ):
                            if start not in search_results[i][name]:
                                search_results[i][name].append(start)

                    start += 1  # Move start forward to continue searching

    return search_results


def extract_fixed_and_regex(hex_pattern):
    """Extracts the fixed sequence and regex pattern from a hex pattern"""
    wildcard_index = hex_pattern.find("..")
    if wildcard_index != -1:
        fixed_sequence = hex_pattern[:wildcard_index]

        regex_pattern = re.compile(hex_pattern[wildcard_index:], re.DOTALL)
        return fixed_sequence, regex_pattern
    return hex_pattern, None  # Return None if there's no regex pattern


def search_in_architectures_with_fixed_sequences_and_regex(
    file_path, architectures, hex_strings
):
    """
    Search for hex patterns in each architecture using fixed sequence and regex,
    by leveraging the single-architecture function.
    """
    search_results = {}
    for i, arch in architectures.items():
        if not arch["valid_macho_header"]:
            continue  # Skip if there isn't a valid Mach-O header

        arch_hex_strings = hex_strings.get(arch["name"], {})
        search_results[i] = {name: [] for name in arch_hex_strings}

        for name, hex_string in arch_hex_strings.items():
            matches = search_with_fixed_sequences_and_regex_for_single_arch(
                file_path, arch, hex_string
            )
            if matches:
                search_results[i][name] = matches

    return search_results


def search_with_fixed_sequences_and_regex_for_single_arch(file_path, arch, hex_string):
    """
    Search for a hex pattern in a single architecture using fixed sequence and regex.
    """
    results = []
    with open(file_path, "rb") as file:
        if not arch["valid_macho_header"]:
            return results

        hex_string = hex_string.replace(" ", "").lower()
        pattern_fixed_prefix, pattern_suffix_regex = extract_fixed_and_regex(hex_string)
        fixed_bytes = bytes.fromhex(pattern_fixed_prefix)

        file.seek(arch["offset"])
        binary_data = file.read(arch["size"])

        start = 0
        while start < len(binary_data):
            start = binary_data.find(fixed_bytes, start)
            if start == -1:
                break  # No more matches

            if pattern_suffix_regex is None:
                results.append(start)  # Found it!
                start += len(fixed_bytes)  # Look for next occurrence
            else:
                remaining_hex_length = len(hex_string) - len(pattern_fixed_prefix)
                remaining_hex_length_bytes = remaining_hex_length // 2

                remaining_start_index = start + len(fixed_bytes)
                remaining_end_index = remaining_start_index + remaining_hex_length_bytes
                hex_string_to_check = binary_data[
                    remaining_start_index:remaining_end_index
                ].hex()

                match = pattern_suffix_regex.match(hex_string_to_check)
                if match:
                    matched_length = len(match.group(0)) // 2
                    results.append(start)  # Found it!
                    start += (
                        len(fixed_bytes) + matched_length
                    )  # Move forward to search for next occurrence
                else:
                    start += len(
                        fixed_bytes
                    )  # No regex match, move start forward past the current fixed sequence

    return results


def search_for_shortest_unique_pattern(file_path, arch, hex_string):
    """
    Search for the shortest unique pattern that matches only a single offset,
    by trimming from the end of the hex string.
    """
    original_length = len(hex_string)
    last_valid_pattern = hex_string  # Initialize with the original pattern
    last_valid_offset = None

    for length in range(original_length, 0, -2):  # Decrease length by 2
        trimmed_hex_string = hex_string[:length]
        matches = search_with_fixed_sequences_and_regex_for_single_arch(
            file_path, arch, trimmed_hex_string
        )

        if len(matches) == 1:
            last_valid_pattern = trimmed_hex_string  # Update last valid pattern
            last_valid_offset = matches[0]
        elif len(matches) != 1:
            break  # Stop if there are no matches or more than one match

    return (
        last_valid_pattern,
        last_valid_offset,
    )  # Return the last valid pattern and offset


def search_in_architectures_with_regex_on_hex_pairs(
    file_path, architectures, hex_strings
):
    search_results = {}

    with open(file_path, "rb") as file:
        for i, arch in architectures.items():
            if not arch["valid_macho_header"]:
                continue

            arch_hex_strings = hex_strings.get(arch["name"], {})
            search_results[i] = {name: [] for name in arch_hex_strings}

            file.seek(arch["offset"])
            binary_data = file.read(arch["size"])
            hex_data = binary_data.hex()

            for name, hex_string in arch_hex_strings.items():
                hex_string = hex_string.replace(" ", "").lower()
                # Convert ".." to regex wildcard ".{2}"
                regex_pattern = hex_string.replace("..", ".{2}")

                for match in re.finditer(regex_pattern, hex_data):
                    # Convert the match start index in hex string to byte index
                    byte_index = match.start() // 2
                    search_results[i][name].append(byte_index)

    return search_results


def hex_to_byte_pattern(hex_string):
    """
    Convert a hex string with wildcards ('..') into a byte regex pattern.
    """

    # Convert the hex string to a byte regex pattern
    byte_regex_pattern = b""
    j = 0
    while j < len(hex_string):
        if hex_string[j : j + 2] == "..":
            byte_regex_pattern += b"."
            j += 2
        else:
            byte_regex_pattern += re.escape(bytes.fromhex(hex_string[j : j + 2]))
            j += 2

    return byte_regex_pattern


def search_in_architectures_with_regex_on_bytes(file_path, architectures, hex_strings):
    search_results = {}

    with open(file_path, "rb") as file:
        for i, arch in architectures.items():
            if not arch["valid_macho_header"]:
                continue

            arch_hex_strings = hex_strings.get(arch["name"], {})
            search_results[i] = {name: [] for name in arch_hex_strings}

            file.seek(arch["offset"])
            binary_data = file.read(arch["size"])

            for name, hex_string in arch_hex_strings.items():
                hex_string = hex_string.replace(" ", "").lower()
                byte_regex_pattern = hex_to_byte_pattern(hex_string)
                pattern = re.compile(byte_regex_pattern)

                for match in pattern.finditer(binary_data):
                    search_results[i][name].append(match.start())

    return search_results


def search_in_architectures_with_rafind2(file_path, architectures, hex_strings):
    """Search for hex strings in each architecture using rafind2 and save their offsets"""
    search_results = {}

    for i, arch in architectures.items():
        if not arch["valid_macho_header"]:
            print(
                f"Warning: Skipping architecture {i} ({arch['name']}) due to invalid Mach-O header."
            )
            continue

        # Get hex strings for the current architecture
        arch_hex_strings = hex_strings.get(arch["name"], {})

        search_results[i] = {}
        for name, hex_string in arch_hex_strings.items():
            offsets = search_with_rafind2(
                file_path, arch["offset"], arch["size"], hex_string
            )
            if offsets is not None:
                search_results[i][name] = offsets

    return search_results


def search_with_rafind2(binary_path, start_offset, size, hex_string):
    """Search for a hex string within a specific architecture of a fat binary using rafind2 and adjust offsets"""
    start_hex = format(start_offset, "x")
    end_hex = format(start_offset + size, "x")

    try:
        # Construct the rafind2 command
        rafind2_command = [
            "rafind2",
            "-f",
            f"0x{start_hex}",
            "-t",
            f"0x{end_hex}",
            "-x",
            hex_string,
            binary_path,
        ]

        # Execute the rafind2 command
        result = subprocess.check_output(rafind2_command, stderr=subprocess.STDOUT)
        result = result.decode("utf-8")

        # Parse and adjust the offsets
        adjusted_offsets = []
        matches = re.findall(r"0x[0-9A-Fa-f]+", result)
        for match in matches:
            offset = int(match, 16)
            adjusted_offset = offset - start_offset
            adjusted_offsets.append(adjusted_offset)

        return adjusted_offsets

    except subprocess.CalledProcessError as e:
        print(f"Error executing rafind2: {e.output.decode('utf-8')}")
        return None


def print_search_results(search_results, architectures, suffix=""):
    """Print the search results for each architecture"""
    print(f"-= Found Hex Offsets{suffix} =-")
    for arch_index, results in search_results.items():
        arch_name = architectures[arch_index]["name"]
        print(f"Architecture {arch_index} ({arch_name}):")
        for name, offsets in results.items():
            offset_strings = [f"0x{offset:x}" for offset in offsets]
            print(f"  {name}: {'; '.join(offset_strings)}")


if __name__ == "__main__":
    main()
