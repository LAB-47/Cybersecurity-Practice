# -*- coding: utf-8 -*-
"""
Windows Shell Link (.LNK) Directory Artifact Forensic Parser
Standard: ISO/IEC 27037 Digital Evidence Handling
Examiner: Ostap Chemerys (Chemeris Ostap)
"""
import io
import sys
import os
import re
import struct
import binascii
import argparse
from dissect.evidence.ewf import EWF
from dissect.ntfs import NTFS
import LnkParse3

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')


def parse_recent_lnk(image_path, user='Joker'):
    if not os.path.exists(image_path):
        print(f"[ERROR] Evidence file not found: {image_path}", file=sys.stderr)
        sys.exit(1)

    print("=" * 80)
    print("WINDOWS SHELL LINK (.LNK) RECENT DIRECTORY ARTIFACT PARSER")
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

    recent_rel_path = f'Users/{user}/AppData/Roaming/Microsoft/Windows/Recent'
    recent_dir = get_rec_by_path(recent_rel_path)
    if not recent_dir:
        print(f"[!] Recent directory not found: {recent_rel_path}")
        return

    print(f"Directory: C:\\{recent_rel_path.replace('/', chr(92))}")
    print(f"MFT Record: #{recent_dir.segment}\n")

    lnk_entries = sorted(recent_dir.listdir().items())
    parsed_links = []

    for name, entry in lnk_entries:
        if not name.lower().endswith('.lnk') or '~1.LNK' in name:
            continue

        rec = entry.dereference()
        if not (rec.header.Flags & 1):
            continue

        rdata = rec.open().read()
        if len(rdata) < 76:
            continue

        hdr_size = struct.unpack('<I', rdata[0:4])[0]
        flags = struct.unpack('<I', rdata[20:24])[0]

        unc_matches = re.findall(rb'\\\\192\.168\.[0-9.]+\\[^\x00\r\n\t]+\.(?:rtf|docx|doc|docs|pdf|png)', rdata, re.IGNORECASE)
        loc_matches = re.findall(rb'[A-Za-z]:\\[^\x00\r\n\t]+\.(?:rtf|docx|doc|docs|pdf|png)', rdata, re.IGNORECASE)

        resolved_target = (unc_matches[0].decode('latin1') if unc_matches else (loc_matches[0].decode('latin1') if loc_matches else "N/A"))

        try:
            lnk = LnkParse3.lnk_file(io.BytesIO(rdata))
            j = lnk.get_json()
            h = j.get('header', {})
            target_size = h.get('target_file_size', 0)
            ctime = h.get('creation_time', 'N/A')
            mtime = h.get('modified_time', 'N/A')
            atime = h.get('accessed_time', 'N/A')
            vsn = j.get('link_info', {}).get('drive_serial_number')
        except Exception:
            target_size, ctime, mtime, atime, vsn = 0, 'N/A', 'N/A', 'N/A', None

        parsed_links.append({
            'name': name,
            'mft': rec.segment,
            'size': len(rdata),
            'target': resolved_target,
            'ctime': ctime,
            'mtime': mtime,
            'atime': atime,
            'vsn': f"0x{vsn:08X}" if vsn else "N/A"
        })

        print(f"[+] LNK File: {name:<25} (MFT #{rec.segment}, File Size: {len(rdata)} bytes)")
        print(f"    LinkFlags:       0x{flags:08X} (Header: {hdr_size} bytes)")
        print(f"    Resolved Target: {resolved_target}")
        print(f"    Target Size:     {target_size} bytes")
        print(f"    Drive Serial:    {f'0x{vsn:08X}' if vsn else 'N/A'}")
        print(f"    Target Created:  {ctime}")
        print(f"    Target Modified: {mtime}")
        print(f"    Target Accessed: {atime}\n")

    print("=" * 80)
    print(f"INVENTORY SUMMARY: {len(parsed_links)} SHELL LINK ARTIFACTS ENUMERATED")
    print("=" * 80)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Windows Shell Link (.LNK) Parser")
    parser.add_argument('--image', default=r'c:\мої локальні файли\AntiIDE\BSidesAmman21.E01\BSidesAmman21.E01',
                        help='Path to E01 evidence file')
    parser.add_argument('--user', default='Joker', help='User profile name')
    args = parser.parse_args()
    parse_recent_lnk(args.image, args.user)
