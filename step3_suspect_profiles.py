# -*- coding: utf-8 -*-
"""
NTFS Master File Table (MFT) Directory Enumeration & User Profile Inventory Tool
Standard: ISO/IEC 27037 Digital Evidence Handling
Examiner: Ostap Chemerys (Chemeris Ostap)
"""
import sys
import os
import argparse
import binascii
from dissect.evidence.ewf import EWF
from dissect.ntfs import NTFS

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')


def enumerate_profiles(image_path, users=('IEUser', 'Joker')):
    if not os.path.exists(image_path):
        print(f"[ERROR] Evidence file not found: {image_path}", file=sys.stderr)
        sys.exit(1)

    print("=" * 80)
    print("MFT DIRECTORY ENUMERATION: USER PROFILES INVENTORY")
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

    # 1. Enumerate and compare directories
    for user in users:
        u_rec = get_rec_by_path(f'Users/{user}')
        if not u_rec:
            print(f"[!] Directory not found: Users/{user}")
            continue

        print(f"\n[+] Profile Directory: C:\\Users\\{user} (MFT Record #{u_rec.segment})")
        print(f"  {'Filename':<35} {'Type':<6} {'MFT #':<8} {'Size (Bytes)':<12}")
        print(f"  {'-' * 35} {'-' * 6} {'-' * 8} {'-' * 12}")

        entries = sorted(u_rec.listdir().items())
        for name, entry in entries:
            rec = entry.dereference()
            t = 'DIR ' if (rec.header.Flags & 2) else 'FILE'
            try:
                sz = rec.size() if t == 'FILE' else 0
            except Exception:
                sz = 0

            if not name.startswith('.') and not '~' in name:
                print(f"  {name:<35} {t:<6} #{rec.segment:<7} {sz:<12}")

    # 2. Extract and inspect resident data of Confidential.rtf
    print("\n" + "=" * 80)
    print("RESIDENT DATA STREAM INSPECTION: C:\\Users\\Joker\\Confidential.rtf")
    print("=" * 80)
    conf_rec = get_rec_by_path('Users/Joker/Confidential.rtf')
    if conf_rec:
        raw_data = conf_rec.open().read()
        print(f"File Path:   C:\\Users\\Joker\\Confidential.rtf")
        print(f"MFT Record:  #{conf_rec.segment}")
        print(f"Stream Type: $DATA (Resident)")
        print(f"Stream Size: {len(raw_data)} bytes\n")
        print("Hex & ASCII Content Dump:")
        for i in range(0, min(len(raw_data), 256), 16):
            chunk = raw_data[i:i + 16]
            hex_str = ' '.join(f'{b:02x}' for b in chunk)
            asc_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
            print(f"  0x{i:04X}:  {hex_str:<48}  |{asc_str}|")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="NTFS Profile Directory Inventory")
    parser.add_argument('--image', default=r'c:\мої локальні файли\AntiIDE\BSidesAmman21.E01\BSidesAmman21.E01',
                        help='Path to E01 evidence file')
    args = parser.parse_args()
    enumerate_profiles(args.image)
