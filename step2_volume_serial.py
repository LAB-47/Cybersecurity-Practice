# -*- coding: utf-8 -*-
"""
NTFS Volume Boot Record (VBR) & Geometry Extractor
"""
import sys
import os
import argparse
import struct
from dissect.evidence.ewf import EWF

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')


def extract_vbr_geometry(image_path):
    if not os.path.exists(image_path):
        print(f"Error: File not found - {image_path}", file=sys.stderr)
        sys.exit(1)

    print("================================================================================")
    print("NTFS VOLUME BOOT RECORD (VBR) SECTOR 0 PARSER")
    print("================================================================================")
    print(f"File Path: {image_path}")

    with open(image_path, 'rb') as fh:
        ewf = EWF(fh)
        stream = ewf.open()
        vbr = stream.read(512)

        print("\n--- Raw Sector 0 Dump (Offset 0x000..0x07F) ---")
        for i in range(0, 128, 16):
            chunk = vbr[i:i + 16]
            hex_str = ' '.join(f'{b:02x}' for b in chunk)
            asc_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
            print(f"  0x{i:03X}:  {hex_str:<48}  |{asc_str}|")

        oem_id = vbr[3:11].decode('ascii', errors='ignore')
        bytes_per_sector = struct.unpack('<H', vbr[11:13])[0]
        sectors_per_cluster = vbr[13]
        total_sectors = struct.unpack('<Q', vbr[40:48])[0]
        mft_lcn = struct.unpack('<Q', vbr[48:56])[0]

        raw_serial_bytes = vbr[0x48:0x50]
        serial_64bit = struct.unpack('<Q', raw_serial_bytes)[0]
        low_32bit = struct.unpack('<I', raw_serial_bytes[0:4])[0]
        vsn_str = f"{low_32bit:08X}"
        vsn_formatted = f"{vsn_str[0:4]}-{vsn_str[4:8]}"

        print("\n--- Parsed VBR Fields ---")
        print(f"OEM ID:               {oem_id.strip()}")
        print(f"Bytes Per Sector:     {bytes_per_sector}")
        print(f"Sectors Per Cluster:  {sectors_per_cluster}")
        print(f"Cluster Size:         {bytes_per_sector * sectors_per_cluster} bytes")
        print(f"Total Sectors:        {total_sectors}")
        print(f"$MFT Starting LCN:    {mft_lcn}")
        print(f"VSN Raw Bytes (LE):   {' '.join(f'{b:02X}' for b in raw_serial_bytes)}")
        print(f"Volume Serial (64-bit):0x{serial_64bit:016X}")
        print(f"Volume Serial (32-bit):{vsn_formatted}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="NTFS VBR Sector 0 Parser")
    parser.add_argument('--image', default=r'c:\мої локальні файли\AntiIDE\BSidesAmman21.E01\BSidesAmman21.E01',
                        help='Path to E01 evidence image')
    args = parser.parse_args()
    extract_vbr_geometry(args.image)
