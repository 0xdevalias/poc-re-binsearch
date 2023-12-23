# Notes

## Unsorted

- https://eclecticlight.co/2020/07/28/universal-binaries-inside-fat-headers/
  - ```
    ⇒ file THE_BINARY
    ⇒ otool -f -v THE_BINARY
    ```
- https://book.hacktricks.xyz/macos-hardening/macos-security-and-privilege-escalation/macos-files-folders-and-binaries/universal-binaries-and-mach-o-format
- https://github.com/Homebrew/ruby-macho/blob/master/lib/macho/headers.rb
- https://docs.python.org/3/library/struct.html#format-characters

We can get the defined symbols from a binary like this:

```bash
⇒ /usr/bin/nm --defined-only --extern-only --arch=x86-64 THE_BINARY
⇒ /usr/bin/nm --defined-only --extern-only --arch=arm64e THE_BINARY
```

We can remove the leading offset from the addresses printed out like this:

```bash
⇒ /usr/bin/nm --defined-only --extern-only --arch=x86_64 THE_BINARY | awk '{print "0x" substr($1, length($1) - 5) " " $2 " " $3}'
⇒ /usr/bin/nm --defined-only --extern-only --arch=arm64e THE_BINARY | awk '{print "0x" substr($1, length($1) - 5) " " $2 " " $3}'
```

## `radare2`

Using `radare2`...

Install it:

```bash
⇒ brew install radare2
```

List architectures in a fat/universal binary:

```bash
⇒ rabin2 -A THE_BINARY
```

eg.

```bash
⇒ rabin2 -A macos-13.3.1-22E261-ventura-arm64-identityservicesd
WARN: run r2 with -e bin.cache=true to fix relocations in disassembly
000 0x00004000 7922416 x86_64 x86 64 all
001 0x00794000 8783712 arm_64 arm64e
```

Specify which architecture of a fat/univeral binary to operate on with `-a x86_64` / `-a arm_64`:

```bash
⇒ rabin2 -a x86_64 OTHER_FLAGS THE_BINARY
⇒ rabin2 -a xarm_64 OTHER_FLAGS THE_BINARY
```

eg.

```bash
⇒ rabin2 -a x86_64 -I macos-13.3.1-22E261-ventura-arm64-identityservicesd | head -n 5
WARN: run r2 with -e bin.cache=true to fix relocations in disassembly
arch     x86
baddr    0x100000000
binsz    7922416
bintype  mach0
bits     64

⇒ rabin2 -a arm_64 -I macos-13.3.1-22E261-ventura-arm64-identityservicesd | head -n 5
WARN: run r2 with -e bin.cache=true to fix relocations in disassembly
arch     arm
baddr    0x100000000
binsz    8783712
bintype  mach0
bits     64
```

List exported symbols + their offsets:

```bash
⇒ rabin2 -E THE_BINARY
⇒ rabin2 -a x86_64 -E THE_BINARY
⇒ rabin2 -a arm_64 -E THE_BINARY
```

eg. `__mh_execute_header` is the macho header for the x86 part (based on the `0x4000` `paddr`) of a fat binary, showing it's offset in the binary (`paddr`), and offset in memory (`vaddr`)

```bash
  [Exports]
  nth paddr      vaddr       bind   type size lib name
  ―――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――
  ..snip..
  21  0x000d0fdf 0x1000ccfdf GLOBAL FUNC 0        _IDSProtoKeyTransparencyTrustedServiceReadFrom
  ..snip..
  55  0x00004000 0x100000000 GLOBAL FUNC 0        __mh_execute_header
  ..snip..
```

This memory offset (`vaddr`) can then be used to calculate the 'offset from base' of a function within that binary when loaded in memory:

```bash
⇒ printf '0x%x\n' $((0x1000ccfdf - 0x100000000))
0xccfdf
```

List all symbols + their offsets:

```bash
⇒ rabin2 -s THE_BINARY
⇒ rabin2 -a x86_64 -s THE_BINARY
⇒ rabin2 -a arm_64 -s THE_BINARY
```

Search for a hex string in binary (using `.` as a wildcard placeholder):

```bash
⇒ rabin2 -x 'HEXPAIRS_WITH_DOT_FOR_WILDCARD' THE_BINARY
```

eg.

```bash
⇒ rafind2 -x '554889e54157415641554154534883ec28..89..48897dd04c8b3d' macos-13.3.1-22E261-ventura-arm64-identityservicesd
0xd0fdf
```

We can then calculate the 'offset from base' of the match based on which architecture it was found in (`rabin2 -A THE_BINARY`):

```bash
⇒ printf '0x%x\n' $((0xd0fdf - 0x4000))
0xccfdf
```

Alternatively, we can wrap it all up as a helper script to automagically do it for us:

NOTE: See [`rafind2-fat-binary`](./rafind2-fat-binary) for an improved version of this script.

```bash
#!/bin/bash

usage() {
    echo "Usage: $0 -a ARCH -b BIN -x HEX"
    echo "  -a ARCH  Specify the architecture to search within the fat binary (e.g., x86_64, arm64)"
    echo "  -b BIN   Specify the binary file to search"
    echo "  -x HEX   Specify the hexadecimal pattern for rafind2"
    echo "  -h       Display this help message"
    exit 1
}

# Parsing command-line arguments
while getopts "a:b:x:h" opt; do
    case $opt in
        a) RE_ARCH="$OPTARG" ;;
        b) RE_BIN="$OPTARG" ;;
        x) FD_HEX="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done

# Check if necessary arguments are provided
if [ -z "$RE_ARCH" ] || [ -z "$RE_BIN" ] || [ -z "$FD_HEX" ]; then
    usage
fi

rabin2 -A "$RE_BIN" | while read -r id offset size arch arch_etc; do
    # Check if the current architecture matches RE_ARCH
    if [ "$arch" != "$RE_ARCH" ]; then
        continue
    fi

    # Calculate the start and end offsets of the desired architecture in the fat/universal binary
    start_hex=$(printf "0x%x" $offset)
    end_hex=$(printf "0x%x" $(($offset + $size)))

    # Running rafind2 with extracted offsets
    results=$(rafind2 -f $start_hex -t $end_hex -x "$FD_HEX" "$RE_BIN")

    # Processing results from rafind2
    echo "-= Results (Raw) =-"
    echo "$results"
    echo
    echo "-= Results (with offsets corrected for arch location in fat/universal binary) =-"
    echo "$results" | awk -v start="$offset" '{if ($1 ~ /^0x[0-9a-f]+$/) printf "0x%x\n", $1 - start}'
done
```

eg.

```bash
⇒ ./rafind2-fat-binary -a x86_64 -b macos-13.3.1-22E261-ventura-arm64-identityservicesd -x '554889e54157415641554154534883ec28..89..48897dd04c8b3d'
  WARN: run r2 with -e bin.cache=true to fix relocations in disassembly
  -= Results (Raw) =-
  0xd0fdf

  -= Results (with offsets corrected for arch location in fat/universal binary) =-
  0xccfdf
```