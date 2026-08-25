# -*- coding: utf-8 -*-
"""
Expert Witness Format (EWF/E01) Header and Integrity Verification Tool
Standard: ISO/IEC 27037 Digital Evidence Handling
Examiner: Ostap Chemerys (Chemeris Ostap)
"""
import sys
import os
import argparse
import hashlib
import binascii
import zlib

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')


def verify_e01_integrity(image_path):
    if not os.path.exists(image_path):
        print(f"[ERROR] Evidence file not found: {image_path}", file=sys.stderr)
        sys.exit(1)

    print("=" * 80)
    print("EWF/E01 EVIDENCE CONTAINER INTEGRITY & METADATA EXTRACTION")
    print("=" * 80)
    print(f"Evidence File: {image_path}")
    print(f"File Size:     {os.path.getsize(image_path):,} bytes")

    # 1. Container Header Signature
    with open(image_path, 'rb') as f:
        magic = f.read(13)
        print(f"Magic Header:  {binascii.hexlify(magic).decode('ascii')} (ASCII: {repr(magic)})")

        # 2. Parse EWF Header Section
        f.seek(0x0D)
        sec_type = f.read(16).rstrip(b'\x00').decode('latin1', errors='ignore')
        next_offset = int.from_bytes(f.read(8), 'little')
        sec_size = int.from_bytes(f.read(8), 'little')
        f.seek(0x0D + 76)
        raw_zlib_header = f.read(sec_size)

        try:
            decompressed_header = zlib.decompress(raw_zlib_header).decode('utf-8', errors='replace')
        except Exception:
            decompressed_header = "N/A (Compressed block)"

        print("\n--- EWF Acquisition Metadata ---")
        print(f"Descriptor Type: {sec_type}")
        print(f"Section Size:    {sec_size} bytes")
        print(f"Next Offset:     0x{next_offset:X}")
        for line in decompressed_header.strip().split('\n'):
            print(f"  {line}")

        # 3. Read Stored MD5 Hash Section (offset 0x15321B877)
        f.seek(0x15321B877)
        raw_hash_block = f.read(0x60)
        raw_md5_bytes = raw_hash_block[0x4C:0x4C + 16]
        embedded_md5 = binascii.hexlify(raw_md5_bytes).decode('ascii')

        print("\n--- Binary Hash Section Dump (Offset: 0x15321B877) ---")
        for i in range(0, len(raw_hash_block), 16):
            chunk = raw_hash_block[i:i + 16]
            hex_str = ' '.join(f'{b:02x}' for b in chunk)
            asc_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
            print(f"  0x{0x15321B877 + i:09X}:  {hex_str:<48}  |{asc_str}|")

        print("\n--- Extracted Evidence Hash Value ---")
        print(f"Embedded Raw Stream MD5: {embedded_md5}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="EWF/E01 Forensic Integrity Verification")
    parser.add_argument('--image', default=r'c:\мої локальні файли\AntiIDE\BSidesAmman21.E01\BSidesAmman21.E01',
                        help='Path to E01 evidence file')
    args = parser.parse_args()
    verify_e01_integrity(args.image)
