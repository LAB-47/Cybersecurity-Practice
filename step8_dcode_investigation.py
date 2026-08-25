# -*- coding: utf-8 -*-
"""
Binary Cryptographic Hash Comparator & Execution Telemetry Extractor
"""
import io
import sys
import os
import struct
import datetime
import codecs
import hashlib
import argparse
from dissect.evidence.ewf import EWF
from dissect.ntfs import NTFS
from Registry import Registry

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')


def extract_binary_telemetry(image_path, file1='Users/Joker/DCode.exe', file2='Users/Joker/dd.exe', user='Joker'):
    if not os.path.exists(image_path):
        print(f"Error: File not found - {image_path}", file=sys.stderr)
        sys.exit(1)

    print("================================================================================")
    print("BINARY CRYPTOGRAPHIC HASH COMPARISON & EXECUTION TELEMETRY")
    print("================================================================================")
    print(f"Evidence File: {image_path}")

    fh = open(image_path, 'rb')
    ewf = EWF(fh)
    fs = NTFS(ewf.open())

    def get_rec_by_path(path):
        parts = [p for p in path.replace('\\\\', '/').replace('\\', '/').strip('/').split('/') if p]
        curr = fs.mft.get(5)
        for part in parts:
            entries = curr.listdir()
            match = None
            for name, entry in entries.items():
                if name.lower() == part.lower():
                    match = entry.dereference()
                    break
            if not match:
                return None
            curr = match
        return curr

    # 1. Cryptographic Hash Comparison
    print("\n--- 1. Cryptographic Hashes ---")
    rec1 = get_rec_by_path(file1)
    rec2 = get_rec_by_path(file2)

    if rec1 and rec2:
        data1 = rec1.open().read()
        data2 = rec2.open().read()

        md5_1 = hashlib.md5(data1).hexdigest()
        sha256_1 = hashlib.sha256(data1).hexdigest()

        md5_2 = hashlib.md5(data2).hexdigest()
        sha256_2 = hashlib.sha256(data2).hexdigest()

        print(f"File 1: C:\\{file1.replace('/', chr(92))} (MFT #{rec1.segment}, {len(data1)} bytes)")
        print(f"  MD5:    {md5_1}")
        print(f"  SHA256: {sha256_1}")

        print(f"File 2: C:\\{file2.replace('/', chr(92))} (MFT #{rec2.segment}, {len(data2)} bytes)")
        print(f"  MD5:    {md5_2}")
        print(f"  SHA256: {sha256_2}")

        print(f"\nHash Comparison Result:")
        print(f"  MD5 Identical:    {md5_1 == md5_2}")
        print(f"  SHA256 Identical: {sha256_1 == sha256_2}")

    # 2. UserAssist Registry Entry
    print("\n--- 2. UserAssist Execution Entry ---")
    ntuser_rec = get_rec_by_path(f'Users/{user}/NTUSER.DAT')
    if ntuser_rec:
        reg = Registry.Registry(io.BytesIO(ntuser_rec.open().read()))
        ua_key = reg.open('Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\\Count')

        for val in ua_key.values():
            raw_name = val.name()
            decoded_name = codecs.decode(raw_name, 'rot_13')

            if 'dd.exe' in decoded_name.lower():
                raw_val = val.raw_data()
                session_id, count, focus_count, focus_time = struct.unpack('<IIII', raw_val[0:16])
                filetime = struct.unpack('<Q', raw_val[60:68])[0]
                dt = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(microseconds=filetime / 10)

                print(f"Registry Key Name:   {raw_name}")
                print(f"Decoded Target Path: {decoded_name}")
                print(f"Execution Counter:   {count}")
                print(f"FILETIME Hex:        0x{filetime:016X}")
                print(f"Timestamp (UTC):     {dt.strftime('%Y-%m-%d %H:%M:%S UTC')}")
                break

    # 3. Prefetch File Descriptor
    print("\n--- 3. Prefetch File Descriptor ---")
    pf_dd = get_rec_by_path('Windows/Prefetch/DD.EXE-0C303FDD.pf')
    if pf_dd:
        si = pf_dd.attributes[16][0].attribute
        print(f"Prefetch Path:     C:\\Windows\\Prefetch\\DD.EXE-0C303FDD.pf (MFT #{pf_dd.segment})")
        print(f"MFT Modified Time: {si.last_modification_time}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Binary Telemetry Extractor")
    parser.add_argument('--image', default=r'c:\мої локальні файли\AntiIDE\BSidesAmman21.E01\BSidesAmman21.E01',
                        help='Path to E01 evidence image')
    args = parser.parse_args()
    extract_binary_telemetry(args.image)
