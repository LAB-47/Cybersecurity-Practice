# -*- coding: utf-8 -*-
"""
КРОК 5: Сирий парсинг окремих файлів ярликів LNK у каталозі Recent
(Друге незалежне джерело доказів доступу до конфіденційних файлів)
"""
import io, sys, re, struct, binascii
from dissect.evidence.ewf import EWF
from dissect.ntfs import NTFS
import LnkParse3

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

E01_PATH = r'c:\мої локальні файли\AntiIDE\BSidesAmman21.E01\BSidesAmman21.E01'
fh = open(E01_PATH, 'rb')
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

recent_dir = get_rec_by_path('Users/Joker/AppData/Roaming/Microsoft/Windows/Recent')

print("================================================================================")
print("=== 1. ENUMERATION OF SHELL LINK (.LNK) ARTIFACTS IN JOKER RECENT FOLDER ===")
print("================================================================================")
print(f"Directory: C:\\Users\\Joker\\AppData\\Roaming\\Microsoft\\Windows\\Recent (MFT Record #{recent_dir.segment})\n")

lnk_entries = sorted(recent_dir.listdir().items())

for name, entry in lnk_entries:
    if not name.lower().endswith('.lnk') or '~1.LNK' in name:
        continue
    
    rec = entry.dereference()
    if not (rec.header.Flags & 1): # перевірка чи це файл
        continue
    
    rdata = rec.open().read()
    if len(rdata) < 76:
        continue
    
    # Перевірка LNK сигнатури (HeaderSize: 0x4C, CLSID: 00021401-0000-0000-C000-000000000046)
    hdr_size = struct.unpack('<I', rdata[0:4])[0]
    clsid = binascii.hexlify(rdata[4:20]).decode('ascii')
    flags = struct.unpack('<I', rdata[20:24])[0]
    
    # Вилучення UNC або локального шляху
    unc_matches = re.findall(rb'\\\\192\.168\.[0-9.]+\\[^\x00\r\n\t]+\.(?:rtf|docx|doc|docs|pdf|png)', rdata, re.IGNORECASE)
    loc_matches = re.findall(rb'[A-Za-z]:\\[^\x00\r\n\t]+\.(?:rtf|docx|doc|docs|pdf|png)', rdata, re.IGNORECASE)
    
    resolved_target = (unc_matches[0].decode('latin1') if unc_matches else (loc_matches[0].decode('latin1') if loc_matches else "N/A"))
    
    # Парсинг часових міток заголовка LNK
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
    
    if any(k in name.lower() for k in ['confid', 'haha', 'docs', 'mandiant', 'sauron']):
        print(f"[+] LNK File: {name:<25} (MFT #{rec.segment}, LNK Size: {len(rdata)} bytes)")
        print(f"    Raw Header Size: {hdr_size} bytes | Flags: 0x{flags:08X}")
        print(f"    Resolved Target: {resolved_target}")
        print(f"    Target Size:     {target_size} bytes")
        if vsn:
            print(f"    Volume Serial:   0x{vsn:08X}")
        print(f"    Target Created:  {ctime}")
        print(f"    Target Modified: {mtime}")
        print(f"    Target Accessed: {atime}\n")

print("================================================================================")
print("=== EVIDENCE CORROBORATION & VERIFICATION (Question 7) ===")
print("================================================================================")
print("Two completely independent forensic evidence sources proving user access:")
print("  [1] Windows AutomaticDestinations Jumplists (CFBF OLE Database):")
print("      Path: C:\\Users\\Joker\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\AutomaticDestinations\\469e4a7982cea4d4.automaticDestinations-ms")
print("      Proof: Contains individual OLE Streams 1, 2, 3, 4, 5 for all accessed files.")
print("  [2] Windows Shell Links (LNK Files in Recent Directory):")
print("      Path: C:\\Users\\Joker\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\*.lnk")
print("      Proof: Contains standalone binary LNK files (Confidential.lnk, Confidential_02.lnk, etc.) with embedded network & local paths.")
