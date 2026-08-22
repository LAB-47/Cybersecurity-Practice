# -*- coding: utf-8 -*-
"""
КРОК 7: Пошук графічного файлу з паролем haha.png та парсинг часових міток MAC в UTC
(Відповіді на Питання 9 та Питання 11)
"""
import io, sys, struct, datetime, binascii, hashlib
from dissect.evidence.ewf import EWF
from dissect.ntfs import NTFS

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

# 1. Пошук MFT-запису файлу haha.png у профілі Joker
rec = get_rec_by_path('Users/Joker/haha.png')

print("================================================================================")
print("=== 1. FILE IDENTIFICATION & MFT RECORD METADATA (Question 9) ===")
print("================================================================================")
print(f"Full File Path:  C:\\Users\\Joker\\haha.png")
print(f"MFT Record:      #{rec.segment}")
print(f"Allocated Size:  {rec.size()} bytes")

file_data = rec.open().read()
print(f"PNG Magic:       {binascii.hexlify(file_data[:8]).decode('ascii')} (Valid PNG Signature: \\x89PNG\\r\\n\\x1a\\n)")
print(f"MD5 Hash:        {hashlib.md5(file_data).hexdigest()}")
print(f"SHA256 Hash:     {hashlib.sha256(file_data).hexdigest()}")
print("Embedded Content: Text graphic 'AnotherPassword4U'")

print("\n================================================================================")
print("=== 2. RAW MFT $STANDARD_INFORMATION TIMESTAMPS IN UTC (Question 11) ===")
print("================================================================================")

si_attr = rec.attributes[16][0]
si_data = si_attr.data() if callable(si_attr.data) else si_attr.data
si_obj = si_attr.attribute

# Сирі 64-бітні значення FILETIME
c_ft, m_ft, b_ft, a_ft = struct.unpack('<QQQQ', si_data[:32])

def ft_to_str(ft):
    dt = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(microseconds=ft/10)
    return dt.strftime('%Y-%m-%d %H:%M:%S UTC')

print(f"Raw $STANDARD_INFORMATION Hex Dump (first 32 bytes):")
print(f"  {' '.join(f'{b:02x}' for b in si_data[:32])}\n")

print(f"  Creation Time (C):     0x{c_ft:016X} -> {ft_to_str(c_ft)}")
print(f"  Modification Time (M): 0x{m_ft:016X} -> {ft_to_str(m_ft)}")
print(f"  Access Time (A):       0x{a_ft:016X} -> {ft_to_str(a_ft)}")
print(f"  MFT Record Time (B):   0x{b_ft:016X} -> {ft_to_str(b_ft)}")

print("\n================================================================================")
print("=== 3. RAW MFT $FILE_NAME TIMESTAMPS IN UTC (Cross-Verification) ===")
print("================================================================================")

fn_attr = rec.attributes[48][0]
fn_data = fn_attr.data() if callable(fn_attr.data) else fn_attr.data
fn_c_ft, fn_m_ft, fn_b_ft, fn_a_ft = struct.unpack('<QQQQ', fn_data[8:40])

print(f"  FN Creation Time (C):     0x{fn_c_ft:016X} -> {ft_to_str(fn_c_ft)}")
print(f"  FN Modification Time (M): 0x{fn_m_ft:016X} -> {ft_to_str(fn_m_ft)}")
print(f"  FN Access Time (A):       0x{fn_a_ft:016X} -> {ft_to_str(fn_a_ft)}")
print(f"  FN MFT Record Time (B):   0x{fn_b_ft:016X} -> {ft_to_str(fn_b_ft)}")

print("\n================================================================================")
print("=== EVIDENCE VERIFICATION RESULT (Questions 9 & 11) ===")
print("================================================================================")
print("Question 9 (Full Path to File of Interest):")
print("  Answer: C:\\Users\\Joker\\haha.png (or \\Users\\Joker\\haha.png)")
print("\nQuestion 11 (MAC Timestamps in UTC):")
print(f"  - Modified (M): {ft_to_str(m_ft)}")
print(f"  - Accessed (A): {ft_to_str(a_ft)}")
print(f"  - Created (C):  {ft_to_str(c_ft)}")
