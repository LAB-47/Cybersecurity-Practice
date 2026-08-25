# -*- coding: utf-8 -*-
"""
КРОК 6: Ідентифікація програми відкриття документів через Prefetch та UserAssist
(Відповідь на Питання 8: WORDPAD.EXE)
"""
import io, sys, re, struct, datetime, codecs, binascii
from dissect.evidence.ewf import EWF
from dissect.ntfs import NTFS
from Registry import Registry

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

print("================================================================================")
print("=== 1. WINDOWS PREFETCH ARTIFACT (Execution Evidence for WordPad) ===")
print("================================================================================")

pf_rec = get_rec_by_path('Windows/Prefetch/WORDPAD.EXE-942EAA71.pf')
if pf_rec:
    pf_data = pf_rec.open().read()
    print(f"Prefetch File:     C:\\Windows\\Prefetch\\WORDPAD.EXE-942EAA71.pf (MFT #{pf_rec.segment})")
    print(f"Prefetch Size:     {len(pf_data)} bytes")
    
    # Вивід сигнатури заголовка Prefetch (MAM - стиснений або SCCA)
    sig = pf_data[:4]
    print(f"Prefetch Header:   {sig} (Hex: {binascii.hexlify(sig).decode('ascii')})")
    
    # Часові мітки MFT для prefetch файлу
    si = pf_rec.attributes[16][0].attribute
    print(f"File Created:      {si.creation_time}")
    print(f"File Modified:     {si.last_modification_time} <-- (Час останнього виконання програми)")

print("\n================================================================================")
print("=== 2. USERASSIST REGISTRY ARTIFACT (Joker NTUSER.DAT ROT13 Analysis) ===")
print("================================================================================")

joker_ntuser_rec = get_rec_by_path('Users/Joker/NTUSER.DAT')
ntuser_data = joker_ntuser_rec.open().read()
reg = Registry.Registry(io.BytesIO(ntuser_data))

ua_key = reg.open('Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\\Count')

wordpad_decoded_name = ""
wordpad_count = 0
wordpad_dt = None

for val in ua_key.values():
    raw_name = val.name()
    decoded_name = codecs.decode(raw_name, 'rot_13')
    
    if 'wordpad' in decoded_name.lower():
        found_wordpad = True
        wordpad_decoded_name = decoded_name
        raw_val = val.raw_data()
        
        # Парсинг бінарної структури UserAssist Win10 (72 байти)
        session_id, wordpad_count, focus_count, focus_time = struct.unpack('<IIII', raw_val[0:16])
        filetime = struct.unpack('<Q', raw_val[60:68])[0]
        wordpad_dt = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(microseconds=filetime/10)
        
        print(f"ROT13 Encrypted Name: {raw_name}")
        print(f"Decoded Program Name: {decoded_name}")
        print(f"Execution Run Count:  {wordpad_count}")
        print(f"Last Execution (UTC): {wordpad_dt.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        print(f"Raw Registry Value Dump (72 bytes):")
        for i in range(0, len(raw_val), 16):
            chunk = raw_val[i:i+16]
            hex_str = ' '.join(f'{b:02x}' for b in chunk)
            asc_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
            print(f"  Offset 0x{i:02X}:  {hex_str:<48}  |{asc_str}|")
        break

print("\n================================================================================")
print("=== EVIDENCE VERIFICATION RESULT (Question 8 - Dynamic Evaluation) ===")
print("================================================================================")
if found_wordpad and pf_rec:
    extracted_app_name = wordpad_decoded_name.split('\\')[-1].upper()
    print(f"Identified Application: {extracted_app_name}")
    print(f"Prefetch Last Modified: {si.last_modification_time} (MFT #{pf_rec.segment})")
    print(f"UserAssist Run Count:   {wordpad_count}")
    print(f"UserAssist Timestamp:   {wordpad_dt.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"Corroboration Match:    {extracted_app_name == 'WORDPAD.EXE' and wordpad_count == 5}")
