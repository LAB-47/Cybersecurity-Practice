# -*- coding: utf-8 -*-
"""
Windows JumpList (AutomaticDestinations-ms) OLE Stream Parser
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


def parse_automaticdestinations_ole(image_path, rel_path='Users/Joker/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/469e4a7982cea4d4.automaticDestinations-ms'):
    if not os.path.exists(image_path):
        print(f"Error: File not found - {image_path}", file=sys.stderr)
        sys.exit(1)

    print("================================================================================")
    print("AUTOMATICDESTINATIONS OLE STRUCTURED STORAGE PARSER")
    print("================================================================================")
    print(f"Evidence File:  {image_path}")
    print(f"Container Path: C:\\{rel_path.replace('/', chr(92))}")

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

    print(f"MFT Record:     #{rec.segment}")
    print(f"Container Size: {rec.size()} bytes\n")

    raw_ole_data = rec.open().read()
    ole = OLE(io.BytesIO(raw_ole_data))

    stream_list = []

    for stream in sorted(ole.root.walk(), key=lambda s: s.name):
        if not stream.is_stream or stream.name == 'DestList':
            continue

        sdata = stream.open().read()

        unc_matches = re.findall(rb'\\\\192\.168\.[0-9.]+\\[^\x00\r\n\t]+\.(?:rtf|docx|doc|docs|pdf|png)', sdata, re.IGNORECASE)
        loc_matches = re.findall(rb'[A-Za-z]:\\[^\x00\r\n\t]+\.(?:rtf|docx|doc|docs|pdf|png)', sdata, re.IGNORECASE)

        local_path = loc_matches[0].decode('latin1', errors='ignore') if loc_matches else None
        unc_path = unc_matches[0].decode('latin1', errors='ignore') if unc_matches else None

        target_type = "NETWORK (UNC)" if unc_path else ("LOCAL (Fixed)" if local_path else "UNKNOWN")
        final_path = unc_path or local_path or "N/A"

        try:
            lnk = LnkParse3.lnk_file(io.BytesIO(sdata))
            j = lnk.get_json()
            h = j.get('header', {})
            ctime = h.get('creation_time', 'N/A')
            mtime = h.get('modified_time', 'N/A')
            atime = h.get('accessed_time', 'N/A')
        except Exception:
            ctime, mtime, atime = 'N/A', 'N/A', 'N/A'

        stream_list.append({
            'stream_id': stream.name,
            'size': len(sdata),
            'type': target_type,
            'path': final_path,
            'ctime': ctime,
            'mtime': mtime,
            'atime': atime
        })

        print(f"[+] OLE Stream ID: {stream.name} ({len(sdata)} bytes)")
        print(f"    Target Location: {target_type}")
        print(f"    Resolved Path:   {final_path}")
        print(f"    Target Created:  {ctime}")
        print(f"    Target Modified: {mtime}")
        print(f"    Target Accessed: {atime}")
        hex_sample = ' '.join(f'{b:02x}' for b in sdata[:32])
        print(f"    Header Bytes:    {hex_sample}\n")

    print("=" * 80)
    print(f"PARSED STREAMS: {len(stream_list)} LNK ENTRIES RESOLVED")
    print("=" * 80)
    for s in stream_list:
        print(f"  Stream #{s['stream_id']} [{s['type']:<15}] {s['path']}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="JumpList OLE Stream Parser")
    parser.add_argument('--image', default=r'c:\мої локальні файли\AntiIDE\BSidesAmman21.E01\BSidesAmman21.E01',
                        help='Path to E01 evidence image')
    args = parser.parse_args()
    parse_automaticdestinations_ole(args.image)
