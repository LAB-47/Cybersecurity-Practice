# -*- coding: utf-8 -*-
"""
NTFS MFT File Attributes & MACB Timestamp Forensic Parser
Standard: ISO/IEC 27037 Digital Evidence Handling
Examiner: Ostap Chemerys (Chemeris Ostap)
"""
import io
import sys
import os
import struct
import datetime
import binascii
import hashlib
import argparse
from dissect.evidence.ewf import EWF
from dissect.ntfs import NTFS

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')


def parse_file_timestamps(image_path, rel_path='Users/Joker/haha.png'):
    if not os.path.exists(image_path):
        print(f"[ERROR] Evidence file not found: {image_path}", file=sys.stderr)
        sys.exit(1)

    print("=" * 80)
    print("NTFS MFT FILE ATTRIBUTES & MACB TIMESTAMPS PARSER")
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

    rec = get_rec_by_path(rel_path)
    if not rec:
        print(f"[!] Target file not found: {rel_path}")
        return

    file_data = rec.open().read()
    md5 = hashlib.md5(file_data).hexdigest()
    sha256 = hashlib.sha256(file_data).hexdigest()

    print(f"Target Path:    C:\\{rel_path.replace('/', chr(92))}")
    print(f"MFT Record:     #{rec.segment}")
    print(f"Allocated Size: {rec.size():,} bytes")
    print(f"Magic Header:   {binascii.hexlify(file_data[:8]).decode('ascii')}")
    print(f"MD5 Hash:       {md5}")
    print(f"SHA-256 Hash:   {sha256}\n")

    # 1. Parse $STANDARD_INFORMATION (0x10)
    print("--- 1. $STANDARD_INFORMATION (0x10) Attributes ---")
    si_attr = rec.attributes[16][0]
    si_data = si_attr.data() if callable(si_attr.data) else si_attr.data
    c_ft, m_ft, b_ft, a_ft = struct.unpack('<QQQQ', si_data[:32])

    def ft_to_str(ft):
        dt = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(microseconds=ft / 10)
        return dt.strftime('%Y-%m-%d %H:%M:%S UTC')

    print(f"Raw 32-Byte Buffer: {' '.join(f'{b:02x}' for b in si_data[:32])}")
    print(f"  Created Time ($SI.C):      0x{c_ft:016X} -> {ft_to_str(c_ft)}")
    print(f"  Modified Time ($SI.M):     0x{m_ft:016X} -> {ft_to_str(m_ft)}")
    print(f"  Accessed Time ($SI.A):     0x{a_ft:016X} -> {ft_to_str(a_ft)}")
    print(f"  MFT Record Modified ($SI.B):0x{b_ft:016X} -> {ft_to_str(b_ft)}\n")

    # 2. Parse $FILE_NAME (0x30)
    print("--- 2. $FILE_NAME (0x30) Attributes ---")
    fn_attr = rec.attributes[48][0]
    fn_data = fn_attr.data() if callable(fn_attr.data) else fn_attr.data
    fn_c_ft, fn_m_ft, fn_b_ft, fn_a_ft = struct.unpack('<QQQQ', fn_data[8:40])

    print(f"  FN Created Time ($FN.C):   0x{fn_c_ft:016X} -> {ft_to_str(fn_c_ft)}")
    print(f"  FN Modified Time ($FN.M):  0x{fn_m_ft:016X} -> {ft_to_str(fn_m_ft)}")
    print(f"  FN Accessed Time ($FN.A):  0x{fn_a_ft:016X} -> {ft_to_str(fn_a_ft)}")
    print(f"  FN MFT Modified ($FN.B):   0x{fn_b_ft:016X} -> {ft_to_str(fn_b_ft)}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="NTFS MFT MACB Timestamp Parser")
    parser.add_argument('--image', default=r'c:\мої локальні файли\AntiIDE\BSidesAmman21.E01\BSidesAmman21.E01',
                        help='Path to E01 evidence file')
    parser.add_argument('--path', default='Users/Joker/haha.png', help='Relative path to target file')
    args = parser.parse_args()
    parse_file_timestamps(args.image, args.path)
