# -*- coding: utf-8 -*-
"""
Master Forensic Verification & Evidence Parser Suite
Case: BSides Amman 2021 DFIR Investigation
Standard: ISO/IEC 27037 Digital Evidence Handling
Examiner: Ostap Chemerys (Chemeris Ostap)
"""
import io
import sys
import os
import re
import struct
import datetime
import codecs
import hashlib
import binascii
import argparse
from dissect.evidence.ewf import EWF
from dissect.ntfs import NTFS
from dissect.ole import OLE
from Registry import Registry
import LnkParse3

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')


def run_master_verification(image_path):
    if not os.path.exists(image_path):
        print(f"[ERROR] Evidence image not found: {image_path}", file=sys.stderr)
        sys.exit(1)

    print("=" * 80)
    print("DIGITAL FORENSICS COMPREHENSIVE VERIFICATION SUITE")
    print("=" * 80)
    print(f"Evidence File: {image_path}")

    # 1. EWF / E01 Integrity
    print("\n[SECTION 1] EWF Container & Stored Hash Extraction")
    with open(image_path, 'rb') as f:
        f.seek(0x15321B877)
        raw_hash_block = f.read(0x60)
        raw_md5_bytes = raw_hash_block[0x4C:0x4C + 16]
        embedded_md5 = binascii.hexlify(raw_md5_bytes).decode('ascii')
        print(f"  Embedded Acquisition Raw MD5: {embedded_md5}")

    # Initialize NTFS Filesystem
    fh = open(image_path, 'rb')
    ewf = EWF(fh)
    stream = ewf.open()
    fs = NTFS(stream)

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

    # 2. VBR & Volume Serial Number
    print("\n[SECTION 2] NTFS Volume Boot Record (VBR) Geometry")
    stream.seek(0)
    vbr = stream.read(512)
    raw_serial_bytes = vbr[0x48:0x50]
    serial_64bit = struct.unpack('<Q', raw_serial_bytes)[0]
    low_32bit = struct.unpack('<I', raw_serial_bytes[0:4])[0]
    vsn_str = f"{low_32bit:08X}"
    vsn_formatted = f"{vsn_str[0:4]}-{vsn_str[4:8]}"
    print(f"  Volume Serial Number (VSN): {vsn_formatted} (64-bit: 0x{serial_64bit:016X})")

    # 3. User Profile Inventory
    print("\n[SECTION 3] User Profile Directory Inventory")
    for u in ['IEUser', 'Joker']:
        rec = get_rec_by_path(f'Users/{u}')
        if rec:
            count = len(rec.listdir())
            print(f"  Directory C:\\Users\\{u:<8} (MFT #{rec.segment:<6}): {count} total directory entries")

    # 4. JumpList & Shell Link Analysis
    print("\n[SECTION 4] WordPad JumpList (AutomaticDestinations) & LNK Artifacts")
    jl_rec = get_rec_by_path('Users/Joker/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/469e4a7982cea4d4.automaticDestinations-ms')
    if jl_rec:
        ole = OLE(io.BytesIO(jl_rec.open().read()))
        for stream_obj in sorted(ole.root.walk(), key=lambda s: s.name):
            if stream_obj.is_stream and stream_obj.name != 'DestList':
                sdata = stream_obj.open().read()
                unc = re.findall(rb'\\\\192\.168\.[0-9.]+\\[^\x00\r\n\t]+\.(?:rtf|docx|doc|docs|pdf|png)', sdata, re.IGNORECASE)
                loc = re.findall(rb'[A-Za-z]:\\[^\x00\r\n\t]+\.(?:rtf|docx|doc|docs|pdf|png)', sdata, re.IGNORECASE)
                res_path = unc[0].decode('latin1') if unc else (loc[0].decode('latin1') if loc else "N/A")
                loc_type = "NETWORK (UNC)" if unc else ("LOCAL (Fixed)" if loc else "UNKNOWN")
                print(f"  Stream #{stream_obj.name:<2} [{loc_type:<13}] {res_path}")

    # 5. Application Execution Artifacts (Prefetch & UserAssist)
    print("\n[SECTION 5] Application Execution Artifacts")
    pf_wp = get_rec_by_path('Windows/Prefetch/WORDPAD.EXE-942EAA71.pf')
    if pf_wp:
        si_wp = pf_wp.attributes[16][0].attribute
        print(f"  WORDPAD.EXE Prefetch MFT #{pf_wp.segment:<6}: Last Modified {si_wp.last_modification_time}")

    ntuser_rec = get_rec_by_path('Users/Joker/NTUSER.DAT')
    if ntuser_rec:
        reg = Registry.Registry(io.BytesIO(ntuser_rec.open().read()))
        ua_key = reg.open('Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\\Count')
        for val in ua_key.values():
            dec_name = codecs.decode(val.name(), 'rot_13')
            if any(k in dec_name.lower() for k in ['wordpad', 'dd.exe']):
                raw_val = val.raw_data()
                count = struct.unpack('<I', raw_val[4:8])[0]
                ft = struct.unpack('<Q', raw_val[60:68])[0]
                dt = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(microseconds=ft / 10)
                print(f"  UserAssist: {dec_name.split(chr(92))[-1]:<15} | Run Count: {count} | Last Used: {dt.strftime('%Y-%m-%d %H:%M:%S UTC')}")

    # 6. File Metadata & Timestamps (haha.png)
    print("\n[SECTION 6] File Metadata & MACB Timestamps (haha.png)")
    rec_png = get_rec_by_path('Users/Joker/haha.png')
    if rec_png:
        si_png = rec_png.attributes[16][0].attribute
        pdata = rec_png.open().read()
        print(f"  File C:\\Users\\Joker\\haha.png (MFT #{rec_png.segment}, Size: {len(pdata)} bytes)")
        print(f"    MD5 Hash:      {hashlib.md5(pdata).hexdigest()}")
        print(f"    Created (C):   {si_png.creation_time}")
        print(f"    Modified (M):  {si_png.last_modification_time}")
        print(f"    Accessed (A):  {si_png.last_access_time}")

    # 7. Binary Comparison (DCode.exe vs dd.exe)
    print("\n[SECTION 7] Binary Integrity Comparison (DCode.exe vs dd.exe)")
    r_dcode = get_rec_by_path('Users/Joker/DCode.exe')
    r_dd = get_rec_by_path('Users/Joker/dd.exe')
    if r_dcode and r_dd:
        h1 = hashlib.md5(r_dcode.open().read()).hexdigest()
        h2 = hashlib.md5(r_dd.open().read()).hexdigest()
        print(f"  DCode.exe MD5: {h1}")
        print(f"  dd.exe    MD5: {h2}")
        print(f"  Binary Identical Match: {h1 == h2}")

    print("\n" + "=" * 80)
    print("VERIFICATION COMPLETE - ALL EVIDENCE EXTRACTED OBJECTIVELY")
    print("=" * 80)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Master Forensic Verification Suite")
    parser.add_argument('--image', default=r'c:\мої локальні файли\AntiIDE\BSidesAmman21.E01\BSidesAmman21.E01',
                        help='Path to E01 evidence file')
    args = parser.parse_args()
    run_master_verification(args.image)
