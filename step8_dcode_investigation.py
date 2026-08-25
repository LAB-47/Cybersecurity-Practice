# -*- coding: utf-8 -*-
"""
Binary Integrity Comparison & Defense Evasion Execution Forensic Parser
Standard: ISO/IEC 27037 Digital Evidence Handling
Examiner: Ostap Chemerys (Chemeris Ostap)
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


def analyze_binary_execution(image_path, user='Joker', file1='Users/Joker/DCode.exe', file2='Users/Joker/dd.exe'):
    if not os.path.exists(image_path):
        print(f"[ERROR] Evidence file not found: {image_path}", file=sys.stderr)
        sys.exit(1)

    print("=" * 80)
    print("BINARY COMPARISON & DEFENSE EVASION EXECUTION ANALYSIS")
    print("=" * 80)

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

    # 1. Binary Hash Comparison
    print("\n--- 1. Cryptographic Hash Comparison ---")
    rec1 = get_rec_by_path(file1)
    rec2 = get_rec_by_path(file2)

    if not rec1 or not rec2:
        print(f"[!] Target files missing for comparison: {file1}, {file2}")
        return

    data1 = rec1.open().read()
    data2 = rec2.open().read()

    md5_1 = hashlib.md5(data1).hexdigest()
    sha256_1 = hashlib.sha256(data1).hexdigest()

    md5_2 = hashlib.md5(data2).hexdigest()
    sha256_2 = hashlib.sha256(data2).hexdigest()

    print(f"File A: C:\\{file1.replace('/', chr(92))} (MFT #{rec1.segment}, {len(data1):,} bytes)")
    print(f"  MD5:    {md5_1}")
    print(f"  SHA256: {sha256_1}")

    print(f"File B: C:\\{file2.replace('/', chr(92))} (MFT #{rec2.segment}, {len(data2):,} bytes)")
    print(f"  MD5:    {md5_2}")
    print(f"  SHA256: {sha256_2}")

    print(f"\nHash Comparison Integrity Check:")
    print(f"  MD5 Match:    {md5_1 == md5_2}")
    print(f"  SHA256 Match: {sha256_1 == sha256_2}")

    # 2. UserAssist Execution Analysis
    print("\n--- 2. UserAssist Execution Analysis (NTUSER.DAT) ---")
    ntuser_rec = get_rec_by_path(f'Users/{user}/NTUSER.DAT')
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
            print(f"Execution Run Count: {count}")
            print(f"Raw FILETIME (Hex):  0x{filetime:016X}")
            print(f"Last Execution UTC:  {dt.strftime('%Y-%m-%d %H:%M:%S UTC')}")
            break

    # 3. Prefetch Corroboration
    print("\n--- 3. Windows Prefetch Execution Corroboration ---")
    pf_dd = get_rec_by_path('Windows/Prefetch/DD.EXE-0C303FDD.pf')
    if pf_dd:
        si = pf_dd.attributes[16][0].attribute
        print(f"Prefetch File:     C:\\Windows\\Prefetch\\DD.EXE-0C303FDD.pf (MFT #{pf_dd.segment})")
        print(f"Prefetch Modified: {si.last_modification_time}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Binary Integrity & Execution Analysis")
    parser.add_argument('--image', default=r'c:\мої локальні файли\AntiIDE\BSidesAmman21.E01\BSidesAmman21.E01',
                        help='Path to E01 evidence file')
    parser.add_argument('--user', default='Joker', help='User profile name')
    args = parser.parse_args()
    analyze_binary_execution(args.image, args.user)
