# -*- coding: utf-8 -*-
"""
EWF / E01 Container Metadata & Binary Hash Extractor
"""
import sys
import os
import argparse
import binascii
import zlib

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')


def extract_e01_metadata(image_path):
    if not os.path.exists(image_path):
        print(f"Error: File not found - {image_path}", file=sys.stderr)
        sys.exit(1)

    print("================================================================================")
    print("EWF CONTAINER HEADER & STORED HASH DESCRIPTOR")
    print("================================================================================")
    print(f"File Path: {image_path}")
    print(f"File Size: {os.path.getsize(image_path)} bytes")

    with open(image_path, 'rb') as f:
        # Signature
        magic = f.read(13)
        print(f"Header Signature (Hex):   {binascii.hexlify(magic).decode('ascii')}")
        print(f"Header Signature (ASCII): {repr(magic)}")

        # Header descriptor section
        f.seek(0x0D)
        sec_type = f.read(16).rstrip(b'\x00').decode('latin1', errors='ignore')
        next_offset = int.from_bytes(f.read(8), 'little')
        sec_size = int.from_bytes(f.read(8), 'little')
        f.seek(0x0D + 76)
        raw_zlib_header = f.read(sec_size)

        try:
            decompressed_header = zlib.decompress(raw_zlib_header).decode('utf-8', errors='replace')
        except Exception:
            decompressed_header = "N/A"

        print(f"Header Section Type:      {sec_type}")
        print(f"Header Section Size:      {sec_size} bytes")
        print(f"Next Section Offset:      0x{next_offset:X}")
        print("\n--- Header Section Fields ---")
        for line in decompressed_header.strip().split('\n'):
            print(f"  {line}")

        # Hash descriptor section at offset 0x15321B877
        f.seek(0x15321B877)
        raw_hash_block = f.read(0x60)
        raw_md5_bytes = raw_hash_block[0x4C:0x4C + 16]
        extracted_md5 = binascii.hexlify(raw_md5_bytes).decode('ascii')

        print("\n--- Binary Hash Section (Offset: 0x15321B877) ---")
        for i in range(0, len(raw_hash_block), 16):
            chunk = raw_hash_block[i:i + 16]
            hex_str = ' '.join(f'{b:02x}' for b in chunk)
            asc_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
            print(f"  0x{0x15321B877 + i:09X}:  {hex_str:<48}  |{asc_str}|")

        print(f"\nExtracted Embedded MD5: {extracted_md5}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="EWF Container Metadata & Stored Hash Extractor")
    parser.add_argument('--image', default=r'c:\мої локальні файли\AntiIDE\BSidesAmman21.E01\BSidesAmman21.E01',
                        help='Path to E01 evidence image')
    args = parser.parse_args()
    extract_e01_metadata(args.image)
