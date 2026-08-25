# -*- coding: utf-8 -*-
"""
Windows AutomaticDestinations JumpList (OLE CFBF) Forensic Parser
Standard: ISO/IEC 27037 Digital Evidence Handling
Examiner: Ostap Chemerys (Chemeris Ostap)
"""
import io
import sys
import os
import re
import argparse
from dissect.evidence.ewf import EWF
from dissect.ntfs import NTFS
from dissect.ole import OLE
import LnkParse3

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')


def parse_jumplist(image_path, app_id='469e4a7982cea4d4', user='Joker'):
    if not os.path.exists(image_path):
        print(f"[ERROR] Evidence file not found: {image_path}", file=sys.stderr)
        sys.exit(1)

    print("=" * 80)
    print("WINDOWS JUMPLIST (AUTOMATICDESTINATIONS) FORENSIC STREAM PARSER")
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

    jumplist_rel_path = f'Users/{user}/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/{app_id}.automaticDestinations-ms'
    rec = get_rec_by_path(jumplist_rel_path)
    if not rec:
        print(f"[!] JumpList file not found: {jumplist_rel_path}")
        return

    print(f"Container Path: C:\\{jumplist_rel_path.replace('/', chr(92))}")
    print(f"MFT Record:     #{rec.segment}")
    print(f"Format:         OLE Compound File Binary Format (CFBF)\n")

    raw_ole_data = rec.open().read()
    ole = OLE(io.BytesIO(raw_ole_data))

    stream_results = []

    for stream in sorted(ole.root.walk(), key=lambda s: s.name):
        if not stream.is_stream or stream.name == 'DestList':
            continue

        sdata = stream.open().read()

        # Dynamic regex extraction of target paths
        unc_matches = re.findall(rb'\\\\192\.168\.[0-9.]+\\[^\x00\r\n\t]+\.(?:rtf|docx|doc|docs|pdf|png)', sdata, re.IGNORECASE)
        loc_matches = re.findall(rb'[A-Za-z]:\\[^\x00\r\n\t]+\.(?:rtf|docx|doc|docs|pdf|png)', sdata, re.IGNORECASE)

        local_path = loc_matches[0].decode('latin1', errors='ignore') if loc_matches else None
        unc_path = unc_matches[0].decode('latin1', errors='ignore') if unc_matches else None

        target_type = "NETWORK (UNC Share)" if unc_path else ("LOCAL (Fixed Disk)" if local_path else "UNKNOWN")
        final_path = unc_path or local_path or "N/A"

        # Dynamic LNK Header parsing
        try:
            lnk = LnkParse3.lnk_file(io.BytesIO(sdata))
            j = lnk.get_json()
            h = j.get('header', {})
            ctime = h.get('creation_time', 'N/A')
            mtime = h.get('modified_time', 'N/A')
            atime = h.get('accessed_time', 'N/A')
        except Exception:
            ctime, mtime, atime = 'N/A', 'N/A', 'N/A'

        stream_results.append({
            'stream_id': stream.name,
            'size': len(sdata),
            'type': target_type,
            'path': final_path,
            'ctime': ctime,
            'mtime': mtime,
            'atime': atime
        })

        print(f"[+] OLE Stream #{stream.name} ({len(sdata)} bytes):")
        print(f"    Target Location: {target_type}")
        print(f"    Resolved Path:   {final_path}")
        print(f"    Target Created:  {ctime}")
        print(f"    Target Modified: {mtime}")
        print(f"    Target Accessed: {atime}")
        hex_sample = ' '.join(f'{b:02x}' for b in sdata[:32])
        print(f"    Raw LNK Header:  {hex_sample}\n")

    print("=" * 80)
    print(f"SUMMARY: {len(stream_results)} TARGET FILES RESOLVED FROM JUMPLIST")
    print("=" * 80)
    for res in stream_results:
        print(f"  [{res['type']:<19}] {res['path']}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Windows JumpList OLE Stream Parser")
    parser.add_argument('--image', default=r'c:\мої локальні файли\AntiIDE\BSidesAmman21.E01\BSidesAmman21.E01',
                        help='Path to E01 evidence file')
    parser.add_argument('--appid', default='469e4a7982cea4d4', help='Application Identifier')
    parser.add_argument('--user', default='Joker', help='User profile name')
    args = parser.parse_args()
    parse_jumplist(args.image, args.appid, args.user)
