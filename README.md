# poc-re-binsearch

Proof of Concept (PoC) code/notes exploring reverse engineering techniques for macOS fat binaries, focusing on binary searching and automatic offset identification.

- [`notes.md`](./notes.md): Some random notes I collected while exploring this, including useful commands/snippets/etc.
- [`find_fat_binary_offsets.py`](`./find_fat_binary_offsets.py`): Python script for searching through a macOS fat/universal binary file to automatically extract offsets that match the specified architectures/patterns (including smart offset adjustments). Includes a number of different search implementations that you can contrast for speed if you enable `PROFILE = True`
  - eg.
    - ```bash
      ⇒ ./find_fat_binary_offsets.py /System/Library/PrivateFrameworks/IDS.framework/identityservicesd.app/Contents/MacOS/identityservicesd
      -= Universal Binary Sections =-
      Architecture 0 (x86_64):
        CPU Type: 16777223 (0x1000007)
        CPU Subtype: 3 (0x3)
        CPU Subtype Capability: 0 (0x0)
        Offset: 0x4000 (Valid Mach-O Header: Yes)
        Size: 7989040
        Align: 14
      Architecture 1 (arm64e):
        CPU Type: 16777228 (0x100000c)
        CPU Subtype: 2 (0x2)
        CPU Subtype Capability: 128 (0x80)
        Offset: 0x7a4000 (Valid Mach-O Header: Yes)
        Size: 8833808
        Align: 14
  
      -= Found Symbol Offsets =-
      Offset of _IDSProtoKeyTransparencyTrustedServiceReadFrom in architecture x86_64: 0x0cc743
      Offset of _IDSProtoKeyTransparencyTrustedServiceReadFrom in architecture arm64e: 0x0b524c
  
      -= Found Hex Offsets (with pure python fixed sequence search + regex) =-
      Architecture 0 (x86_64):
        IDSProtoKeyTransparencyTrustedServiceReadFrom: 0xcc743
        NACInitAddress: 0x4b91e0
        NACKeyEstablishmentAddress: 0x499220
        NACSignAddress: 0x4ac510
      Architecture 1 (arm64e):
      ```
    - See also:
      - https://github.com/beeper/mac-registration-provider
        - > A small service that generates iMessage registration data on a Mac
      - https://github.com/beeper/mac-registration-provider/pull/7
        - > add offsets for `13.3.1` (x86/arm64) + `13.5` (x86)
        - https://github.com/beeper/mac-registration-provider/pull/7#issuecomment-1867733658
          - > I've also been working on a PoC script that is able to find the offsets automagically
- [`find_bytes.py`](./find_bytes.py): Quick/dirty python script to find hex bytes in a binary file (no smarts)
- [`rafind2-fat-binary`](./rafind2-fat-binary): Helper script that uses `radare2`'s `rabin` + `rafind2` to search for a hex string (with potential wildcards) in the specified architecture of a macOS fat/universal binary
- Some tests for recursively searching binary files for a hex string (with potential wildcards) using `radare2`'s `rafind2`:
  - [`test-fd-and-rafind2`](./test-fd-and-rafind2) (fastest)
  - [`test-find-and-rafind2`](./test-find-and-rafind2)
  - [`test-grep-and-rafind2`](./test-grep-and-rafind2) (slowest)
- etc
