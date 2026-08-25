# -*- coding: utf-8 -*-
"""
Windows Application Execution Evidence Parser (Prefetch & UserAssist)
Standard: ISO/IEC 27037 Digital Evidence Handling
Examiner: Ostap Chemerys (Chemeris Ostap)
"""
import io
import sys
import os
import struct
import datetime
import codecs
import binascii
import argparse
from dissect.evidence.ewf import EWF
from dissect.ntfs import NTFS
from Registry import Registry

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')


def parse_execution_artifacts(image_path, user='Joker', target_app='wordpad'):
    if not os.path.exists(image_path):
        print(f"[ERROR] Evidence file not found: {image_path}", file=sys.stderr)
        sys.exit(1)

    print("=" * 80)
    print("APPLICATION EXECUTION ARTIFACTS PARSER (PREFETCH & USERASSIST)")
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

    # 1. Windows Prefetch Inspection
    print("\n--- 1. Windows Prefetch Artifact Inspection ---")
    pf_path = 'Windows/Prefetch/WORDPAD.EXE-942EAA71.pf'
    pf_rec = get_rec_by_path(pf_path)
    if pf_rec:
        pf_data = pf_rec.open().read()
        si = pf_rec.attributes[16][0].attribute
        print(f"Prefetch File:     C:\\{pf_path.replace('/', chr(92))}")
        print(f"MFT Record:        #{pf_rec.segment}")
        print(f"File Size:         {len(pf_data):,} bytes")
        print(f"Header Signature:  {pf_data[:4]} (Hex: {binascii.hexlify(pf_data[:4]).decode('ascii')})")
        print(f"File Created:      {si.creation_time}")
        print(f"File Modified:     {si.last_modification_time} (SysMain Flush Timestamp)")
    else:
        print(f"[!] Prefetch file not found: {pf_path}")

    # 2. UserAssist Registry Hive Analysis
    print("\n--- 2. NTUSER.DAT UserAssist Artifact Analysis ---")
    ntuser_path = f'Users/{user}/NTUSER.DAT'
    ntuser_rec = get_rec_by_path(ntuser_path)
    if not ntuser_rec:
        print(f"[!] NTUSER.DAT not found: {ntuser_path}")
        return

    ntuser_data = ntuser_rec.open().read()
    reg = Registry.Registry(io.BytesIO(ntuser_data))
    ua_key = reg.open('Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\\Count')

    for val in ua_key.values():
        raw_name = val.name()
        decoded_name = codecs.decode(raw_name, 'rot_13')

        if target_app.lower() in decoded_name.lower():
            raw_val = val.raw_data()
            session_id, count, focus_count, focus_time = struct.unpack('<IIII', raw_val[0:16])
            filetime = struct.unpack('<Q', raw_val[60:68])[0]
            dt = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(microseconds=filetime / 10)

            print(f"Registry Value:      {raw_name}")
            print(f"Decoded Application: {decoded_name}")
            print(f"Execution Run Count: {count}")
            print(f"Raw FILETIME (Hex):  0x{filetime:016X}")
            print(f"Last Execution UTC:  {dt.strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
            print("Raw Binary Structure Dump (72 Bytes):")
            for i in range(0, len(raw_val), 16):
                chunk = raw_val[i:i + 16]
                hex_str = ' '.join(f'{b:02x}' for b in chunk)
                asc_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
                print(f"  Offset 0x{i:02X}:  {hex_str:<48}  |{asc_str}|")
            break


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Application Execution Evidence Parser")
    parser.add_argument('--image', default=r'c:\мої локальні файли\AntiIDE\BSidesAmman21.E01\BSidesAmman21.E01',
                        help='Path to E01 evidence file')
    parser.add_argument('--user', default='Joker', help='User profile name')
    parser.add_argument('--app', default='wordpad', help='Target application name')
    args = parser.parse_args()
    parse_execution_artifacts(args.image, args.user, args.app)
