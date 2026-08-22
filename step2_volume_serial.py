# -*- coding: utf-8 -*-
"""
КРОК 2: Вилучення серійного номера тому (Volume Serial Number) з сирих байтів VBR
"""
import sys, struct, binascii
from dissect.evidence.ewf import EWF

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

E01_PATH = r'c:\мої локальні файли\AntiIDE\BSidesAmman21.E01\BSidesAmman21.E01'

with open(E01_PATH, 'rb') as fh:
    ewf = EWF(fh)
    stream = ewf.open()
    
    # 1. Зчитування 512 байтів завантажувального сектора NTFS (VBR - Sector 0)
    vbr = stream.read(512)
    
    print("=== RAW NTFS VOLUME BOOT RECORD (VBR) SECTOR 0 DUMP ===")
    for i in range(0, 128, 16):
        chunk = vbr[i:i+16]
        hex_str = ' '.join(f'{b:02x}' for b in chunk)
        asc_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
        print(f"  Offset 0x{i:03X}:  {hex_str:<48}  |{asc_str}|")
    
    # 2. Розбір критичних полів VBR
    oem_id = vbr[3:11].decode('ascii', errors='ignore')
    bytes_per_sector = struct.unpack('<H', vbr[11:13])[0]
    sectors_per_cluster = vbr[13]
    total_sectors = struct.unpack('<Q', vbr[40:48])[0]
    mft_lcn = struct.unpack('<Q', vbr[48:56])[0]
    
    # Серійний номер тому розташований за зміщенням 0x48 (8 байт)
    raw_serial_bytes = vbr[0x48:0x50]
    serial_64bit = struct.unpack('<Q', raw_serial_bytes)[0]
    
    print("\n=== PARSED VBR STRUCTURE FIELDS ===")
    print(f"OEM File System ID:     {oem_id}")
    print(f"Bytes Per Sector:       {bytes_per_sector}")
    print(f"Sectors Per Cluster:    {sectors_per_cluster} (Cluster size: {bytes_per_sector * sectors_per_cluster} bytes)")
    print(f"Total Volume Sectors:   {total_sectors}")
    print(f"$MFT Starting LCN:      {mft_lcn}")
    
    print("\n=== RAW VOLUME SERIAL NUMBER BYTES (Offset 0x48..0x4F) ===")
    print(f"Raw Bytes (Little-Endian): {' '.join(f'{b:02X}' for b in raw_serial_bytes)}")
    print(f"Full 64-bit NTFS Serial:   0x{serial_64bit:016X}")
    
    # Стандартний формат Windows VSN: старші 4 байти (High Word) та молодші 4 байти (Low Word)
    # 32-бітний VSN, що відображається командою DIR/VOL: молодші 4 байти
    low_32bit = struct.unpack('<I', raw_serial_bytes[0:4])[0]
    vsn_str = f"{low_32bit:08X}"
    vsn_formatted = f"{vsn_str[0:4]}-{vsn_str[4:8]}"
    
    print("\n=== EVIDENCE VERIFICATION RESULT (Question 10) ===")
    print(f"Extracted Volume Serial Number: {vsn_formatted}")
    print(f"Target Exam Value:              68D6-28DB")
    print(f"Serial Match Verified:          {vsn_formatted.upper() == '68D6-28DB'}")
