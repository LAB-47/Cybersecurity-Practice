# -*- coding: utf-8 -*-
"""
КРОК 1: Перевірка цілісності та вилучення сирого хешу з контейнера E01
"""
import sys, re, binascii

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

E01_PATH = r'c:\мої локальні файли\AntiIDE\BSidesAmman21.E01\BSidesAmman21.E01'

with open(E01_PATH, 'rb') as f:
    # 1. Сирий заголовок EWF
    magic = f.read(13)
    print("=== RAW EWF FILE SIGNATURE ===")
    print(f"Hex: {binascii.hexlify(magic).decode('ascii')}")
    print(f"ASCII: {magic}\n")
    
    # 2. Зчитування та декомпресія заголовка (Header section)
    f.seek(0x0D)
    sec_type = f.read(16).rstrip(b'\x00').decode('latin1', errors='ignore')
    next_offset = int.from_bytes(f.read(8), 'little')
    sec_size = int.from_bytes(f.read(8), 'little')
    f.seek(0x0D + 76) # початок zlib потоку
    raw_zlib_header = f.read(sec_size)
    try:
        import zlib
        decompressed_header = zlib.decompress(raw_zlib_header).decode('utf-8', errors='replace')
    except Exception:
        decompressed_header = "Raw zlib stream"
    
    print("=== RAW CONTAINER HEADER METADATA (DECOMPRESSED) ===")
    print(f"Section Type:   {sec_type}")
    print(f"Section Size:   {sec_size} bytes")
    print(f"Next Offset:    0x{next_offset:X}")
    print("Header Fields (TSV):")
    for line in decompressed_header.strip().split('\n'):
        print(f"  {line}")
    print()
    
    # 3. Сирий дамп секції HASH (знаходиться в кінці файлу за зміщенням 0x15321B877)
    f.seek(0x15321B877)
    raw_hash_block = f.read(0x60)
    print("=== RAW HASH SECTION BINARY DUMP (Offset: 0x15321B877) ===")
    for i in range(0, len(raw_hash_block), 16):
        chunk = raw_hash_block[i:i+16]
        hex_str = ' '.join(f'{b:02x}' for b in chunk)
        asc_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
        print(f"  {0x15321B877 + i:09X}:  {hex_str:<48}  |{asc_str}|")
    
    # 4. Витяг 16 сирих байтів MD5 (за зміщенням +0x4C від початку секції hash)
    raw_md5_bytes = raw_hash_block[0x4C:0x4C+16]
    extracted_md5 = binascii.hexlify(raw_md5_bytes).decode('ascii')
    
    print("\n=== EVIDENCE VERIFICATION RESULT ===")
    print(f"Raw MD5 Bytes:       {binascii.hexlify(raw_md5_bytes).decode('ascii')}")
    print(f"Formatted Hex MD5:   {extracted_md5}")
    print(f"Target Exam MD5:     634ed59c1cf60ef0a7f62e06529b2b2d")
    print(f"Hash Match Verified: {extracted_md5.lower() == '634ed59c1cf60ef0a7f62e06529b2b2d'}")
