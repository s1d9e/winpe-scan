#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║                      WINPE-SCAN v1.0                          ║
║           ╔═══════════════════════════════════════╗            ║
║           ║   "Knowledge is power, but analysis  ║            ║
║           ║    is understanding..."              ║            ║
║           ╚═══════════════════════════════════════╝            ║
╚══════════════════════════════════════════════════════════════════╝

Windows PE Multi-Tool Analyzer
A comprehensive toolkit for PE file analysis.

[!] FOR EDUCATIONAL PURPOSES ONLY

Tools:
  info       - Full PE analysis
  strings    - Extract strings
  hash       - Calculate hashes
  headers    - View PE headers
  sections   - Analyze sections
  imports    - List imports/exports
  compare    - Compare two PE files
  sig        - Check digital signatures
"""

import struct
import os
import sys
import hashlib
import argparse
import json
import re
from datetime import datetime
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, asdict
from colorama import init, Fore, Back, Style

init(autoreset=True)

@dataclass
class PESection:
    name: str
    virtual_address: int
    virtual_size: int
    raw_size: int
    raw_offset: int
    entropy: float
    flags: List[str]
    
@dataclass
class ImportEntry:
    dll: str
    functions: List[str]
    
@dataclass
class ExportEntry:
    ordinal: int
    name: str
    address: int

@dataclass
class PEInfo:
    filename: str
    file_size: int
    hashes: Dict[str, str]
    machine: str
    subsystem: str
    timestamp: str
    entry_point: str
    image_base: str
    linker_version: str
    os_version: str
    sections: List[dict]
    imports: List[dict]
    exports: List[dict]
    resources: List[dict]
    strings: List[str]
    suspicious: List[dict]

class Colors:
    RED = Fore.RED
    GREEN = Fore.GREEN
    YELLOW = Fore.YELLOW
    BLUE = Fore.BLUE
    CYAN = Fore.CYAN
    MAGENTA = Fore.MAGENTA
    WHITE = Fore.WHITE
    DIM = Fore.LIGHTBLACK_EX
    RESET = Style.RESET_ALL
    BOLD = Style.BRIGHT

class Banner:
    @staticmethod
    def main():
        return f"""
{Colors.RED}╔{'═' * 66}╗
║{' ' * 17}{Colors.YELLOW}WINPE-SCAN{Colors.RED}{' ' * 29}║
║{' ' * 12}{Colors.CYAN}Windows PE Multi-Tool Analyzer{Colors.RED}{' ' * 22}║
╚{'═' * 66}╝{Colors.RESET}

{Colors.DIM}Tools:{Colors.WHITE} info | strings | hash | headers | sections | imports | compare | sig
{Colors.DIM}Usage:{Colors.WHITE} winpe-scan.py <tool> [options]
{Colors.DIM}Help:{Colors.WHITE}  winpe-scan.py <tool> --help{Colors.RESET}
"""

class PEAnalyzer:
    COMMON_DLLS = [
        "kernel32.dll", "ntdll.dll", "user32.dll", "gdi32.dll",
        "advapi32.dll", "ws2_32.dll", "wininet.dll", "urlmon.dll",
        "shlwapi.dll", "shell32.dll", "ole32.dll", "oleaut32.dll",
        "msvcrt.dll", "comctl32.dll", "comdlg32.dll", "version.dll",
    ]
    
    SUSPICIOUS_PATTERNS = {
        "network": [r'https?://[^\s]+\.[a-z]{2,}', r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', r'socket|connect|send'],
        "command": [r'cmd\.exe|powershell|bash|/c\s+|/k\s+', r'CreateProcess|ShellExecute'],
        "crypto": [r'CryptEncrypt|CryptDecrypt|MD5|SHA1|Base64'],
        "registry": [r'RegOpenKey|RegSetValue|SOFTWARE\\|SYSTEM\\'],
        "mutex": [r'Mutex|CreateMutex'],
        "services": [r'CreateService|StartService|ServiceMain'],
    }
    
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.filename = os.path.basename(filepath)
        self.data = None
        self.file_size = 0
        self.is_valid_pe = False
        self.pe_offset = 0
        self.file_header = None
        self.optional_header = None
        self.sections: List[PESection] = []
        self.imports: List[ImportEntry] = []
        self.exports: List[ExportEntry] = []
        self.strings: List[str] = []
        self.suspicious: List[Dict] = []
        
    def load(self) -> bool:
        try:
            with open(self.filepath, 'rb') as f:
                self.data = f.read()
            self.file_size = len(self.data)
            return True
        except Exception as e:
            print(f"{Colors.RED}[!] Error loading file: {e}{Colors.RESET}")
            return False
            
    def parse_pe(self) -> bool:
        if len(self.data) < 64:
            return False
        if struct.unpack('<H', self.data[0:2])[0] != 0x5A4D:
            return False
        self.pe_offset = struct.unpack('<I', self.data[60:64])[0]
        if self.data[self.pe_offset:self.pe_offset+4] != b'PE\x00\x00':
            return False
        self.is_valid_pe = True
        self._parse_file_header()
        self._parse_optional_header()
        self._parse_sections()
        return True
        
    def _parse_file_header(self):
        offset = self.pe_offset + 4
        self.file_header = {
            'machine': struct.unpack('<H', self.data[offset:offset+2])[0],
            'num_sections': struct.unpack('<H', self.data[offset+2:offset+4])[0],
            'timestamp': struct.unpack('<I', self.data[offset+4:offset+8])[0],
            'opt_header_size': struct.unpack('<H', self.data[offset+16:offset+18])[0],
        }
        
    def _parse_optional_header(self):
        offset = self.pe_offset + 24
        magic = struct.unpack('<H', self.data[offset:offset+2])[0]
        self.optional_header = {
            'magic': magic,
            'linker_ver': f"{self.data[offset+2]}.{self.data[offset+3]}",
            'entry_point': struct.unpack('<I', self.data[offset+16:offset+20])[0],
        }
        if magic == 0x10b:
            self.optional_header['image_base'] = struct.unpack('<I', self.data[offset+28:offset+32])[0]
            self.optional_header['subsystem'] = struct.unpack('<H', self.data[offset+68:offset+70])[0]
        elif magic == 0x20b:
            self.optional_header['image_base'] = struct.unpack('<Q', self.data[offset+24:offset+32])[0]
            self.optional_header['subsystem'] = struct.unpack('<H', self.data[offset+88:offset+90])[0]
            
    def _parse_sections(self):
        offset = self.pe_offset + 24 + self.file_header['opt_header_size']
        for i in range(self.file_header['num_sections']):
            off = offset + (i * 40)
            if off + 40 > len(self.data):
                break
            name = self.data[off:off+8].rstrip(b'\x00').decode('ascii', errors='ignore')
            virt_size = struct.unpack('<I', self.data[off+8:off+12])[0]
            virt_addr = struct.unpack('<I', self.data[off+12:off+16])[0]
            raw_size = struct.unpack('<I', self.data[off+16:off+20])[0]
            raw_offset = struct.unpack('<I', self.data[off+20:off+24])[0]
            chars = struct.unpack('<I', self.data[off+36:off+40])[0]
            flags = []
            if chars & 0x20000000: flags.append('EXEC')
            if chars & 0x40000000: flags.append('READ')
            if chars & 0x80000000: flags.append('WRITE')
            if chars & 0x20: flags.append('CODE')
            entropy = self._calc_entropy(raw_offset, raw_size)
            self.sections.append(PESection(name, virt_addr, virt_size, raw_size, raw_offset, entropy, flags))
            
    def _calc_entropy(self, offset: int, size: int) -> float:
        if size == 0 or offset + size > len(self.data):
            return 0.0
        section_data = self.data[offset:offset+size]
        if not section_data:
            return 0.0
        freq = [0] * 256
        for b in section_data:
            freq[b] += 1
        entropy = 0
        for f in freq:
            if f == 0:
                continue
            p = f / len(section_data)
            entropy -= p * (p.bit_length())
        return round(abs(entropy), 2)
        
    def parse_imports(self):
        if not self.optional_header or self.optional_header['magic'] != 0x10b:
            return
        offset = self.pe_offset + 24 + 104
        import_rva = struct.unpack('<I', self.data[offset:offset+4])[0]
        if import_rva == 0:
            return
        off = self._rva_to_offset(import_rva)
        if off == 0:
            return
        seen = set()
        pos = off
        while True:
            if pos + 20 > len(self.data):
                break
            name_rva = struct.unpack('<I', self.data[pos+12:pos+16])[0]
            if name_rva == 0:
                break
            name_off = self._rva_to_offset(name_rva)
            if name_off > 0:
                dll = self.read_string(name_off).lower()
                if dll and dll not in seen:
                    seen.add(dll)
                    funcs = self._get_import_funcs(pos)
                    self.imports.append(ImportEntry(dll, funcs[:20]))
            pos += 20
            
    def _get_import_funcs(self, ilt_offset: int) -> List[str]:
        funcs = []
        pos = ilt_offset
        while pos + 4 <= len(self.data):
            rva = struct.unpack('<I', self.data[pos:pos+4])[0]
            if rva == 0:
                break
            if rva & 0x80000000:
                funcs.append(f"Ordinal#{rva & 0x7FFFFFFF}")
            else:
                off = self._rva_to_offset(rva + 2)
                if off > 0:
                    name = self.read_string(off)
                    if name:
                        funcs.append(name)
            pos += 4
        return funcs
        
    def parse_exports(self):
        if not self.optional_header or self.optional_header['magic'] != 0x10b:
            return
        offset = self.pe_offset + 24 + 96
        exp_rva = struct.unpack('<I', self.data[offset:offset+4])[0]
        if exp_rva == 0:
            return
        off = self._rva_to_offset(exp_rva)
        if off + 24 > len(self.data):
            return
        num_names = struct.unpack('<I', self.data[off+24:off+28])[0]
        name_ptr_rva = struct.unpack('<I', self.data[off+32:off+36])[0]
        ord_base = struct.unpack('<I', self.data[off+36:off+40])[0]
        name_ptr_off = self._rva_to_offset(name_ptr_rva)
        for i in range(min(num_names, 100)):
            try:
                n_off = self._rva_to_offset(struct.unpack('<I', self.data[name_ptr_off + i*4:name_ptr_off + i*4 + 4])[0])
                if n_off > 0:
                    name = self.read_string(n_off)
                    if name:
                        self.exports.append(ExportEntry(ord_base + i, name, 0))
            except:
                break
                
    def extract_strings(self, min_len=4):
        patterns = [
            (b'[\x20-\x7e]{' + str(min_len).encode() + b',}', 'ascii'),
            (b'(?:[\x20-\x7e]\x00){' + str(min_len).encode() + b',}', 'utf16'),
        ]
        strings_set = set()
        for pattern, enc in patterns:
            for match in re.finditer(pattern, self.data):
                s = match.group(0)
                if enc == 'utf16':
                    s = s.decode('utf-16-le', errors='ignore')
                else:
                    s = s.decode('ascii', errors='ignore')
                if len(s) >= min_len:
                    strings_set.add(s)
        self.strings = sorted(strings_set, key=len, reverse=True)
        
    def detect_suspicious(self):
        for cat, patterns in self.SUSPICIOUS_PATTERNS.items():
            for p in patterns:
                for s in self.strings:
                    if re.search(p, s, re.IGNORECASE):
                        self.suspicious.append({
                            'category': cat.upper(),
                            'pattern': p,
                            'string': s[:80],
                            'severity': 'HIGH' if cat in ['command', 'crypto'] else 'MEDIUM'
                        })
                        
    def _rva_to_offset(self, rva: int) -> int:
        for sec in self.sections:
            if sec.virtual_address <= rva < sec.virtual_address + sec.virtual_size:
                return rva - sec.virtual_address + sec.raw_offset
        return 0
        
    def read_string(self, offset: int, max_len=256) -> str:
        if offset >= len(self.data):
            return ""
        end = offset
        while end < len(self.data) and end < offset + max_len:
            if self.data[end] == 0:
                break
            end += 1
        return self.data[offset:end].decode('ascii', errors='ignore')


def cmd_info(args):
    """Full PE analysis"""
    if not os.path.exists(args.file):
        print(f"{Colors.RED}[!] File not found: {args.file}{Colors.RESET}")
        return 1
        
    pe = PEAnalyzer(args.file)
    if not pe.load():
        return 1
        
    if not pe.parse_pe():
        print(f"{Colors.RED}[!] Not a valid PE file{Colors.RESET}")
        return 1
        
    pe.parse_imports()
    pe.parse_exports()
    pe.extract_strings(min_len=args.min_length)
    pe.detect_suspicious()
    
    hashes = {
        'MD5': hashlib.md5(pe.data).hexdigest(),
        'SHA1': hashlib.sha1(pe.data).hexdigest(),
        'SHA256': hashlib.sha256(pe.data).hexdigest(),
    }
    
    machine_map = {0x14c: 'x86', 0x8664: 'x64', 0x1c0: 'ARM', 0xaa64: 'ARM64'}
    subsystem_map = {1: 'Native', 2: 'Windows GUI', 3: 'Windows CUI', 7: 'POSIX'}
    
    machine = machine_map.get(pe.file_header['machine'], 'Unknown')
    subsystem = subsystem_map.get(pe.optional_header.get('subsystem', 0), 'Unknown')
    
    ts = pe.file_header['timestamp']
    try:
        date_str = datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
    except:
        date_str = 'Unknown'
    
    print(f"""
{Colors.CYAN}[ BASIC INFO ]{Colors.RESET}
{Colors.DIM}{'─' * 50}{Colors.RESET}
  {Colors.WHITE}File:{Colors.RESET}     {Colors.CYAN}{pe.filename}{Colors.RESET}
  {Colors.WHITE}Size:{Colors.RESET}     {Colors.CYAN}{pe.file_size:,} bytes{Colors.RESET}
  {Colors.WHITE}MD5:{Colors.RESET}      {Colors.YELLOW}{hashes['MD5']}{Colors.RESET}
  {Colors.WHITE}SHA256:{Colors.RESET}   {Colors.YELLOW}{hashes['SHA256'][:32]}...{Colors.RESET}

{Colors.CYAN}[ PE HEADERS ]{Colors.RESET}
{Colors.DIM}{'─' * 50}{Colors.RESET}
  {Colors.WHITE}Machine:{Colors.RESET}      {Colors.GREEN}{machine}{Colors.RESET}
  {Colors.WHITE}Sections:{Colors.RESET}     {Colors.GREEN}{pe.file_header['num_sections']}{Colors.RESET}
  {Colors.WHITE}Subsystem:{Colors.RESET}    {Colors.GREEN}{subsystem}{Colors.RESET}
  {Colors.WHITE}Entry Point:{Colors.RESET}  {Colors.CYAN}0x{pe.optional_header['entry_point']:08X}{Colors.RESET}
  {Colors.WHITE}Image Base:{Colors.RESET}   {Colors.CYAN}0x{pe.optional_header['image_base']:X}{Colors.RESET}
  {Colors.WHITE}Timestamp:{Colors.RESET}     {Colors.CYAN}{date_str}{Colors.RESET}

{Colors.CYAN}[ SECTIONS ({len(pe.sections)}) ]{Colors.RESET}
{Colors.DIM}{'─' * 50}{Colors.RESET}
  {Colors.WHITE}{'Name':<10} {'VirtAddr':<12} {'VirtSize':<10} {'RawSize':<10} {'Entropy':<8}{Colors.RESET}
{Colors.DIM}{'─' * 50}{Colors.RESET}""")
    
    for s in pe.sections:
        ent_color = Colors.GREEN if s.entropy < 5 else Colors.YELLOW if s.entropy < 7 else Colors.RED
        print(f"  {Colors.WHITE}{s.name:<10} {Colors.CYAN}0x{s.virtual_address:08X}{Colors.RESET} "
              f"{Colors.CYAN}0x{s.virtual_size:08X}{Colors.RESET} {Colors.CYAN}0x{s.raw_size:08X}{Colors.RESET} "
              f"{ent_color}{s.entropy:<8.2f}{Colors.RESET} {Colors.DIM}{' '.join(s.flags)}{Colors.RESET}")
    
    print(f"""
{Colors.CYAN}[ IMPORTS ({len(pe.imports)}) ]{Colors.RESET}
{Colors.DIM}{'─' * 50}{Colors.RESET}""")
    if pe.imports:
        for imp in pe.imports[:15]:
            dll = imp.dll.replace('.dll', '')
            funcs = ', '.join(imp.functions[:8])
            if len(imp.functions) > 8:
                funcs += f" {Colors.DIM}...+{len(imp.functions)-8}{Colors.RESET}"
            print(f"  {Colors.GREEN}{dll}.dll{Colors.RESET} → {funcs}")
    else:
        print(f"  {Colors.DIM}No imports found{Colors.RESET}")
    
    print(f"""
{Colors.CYAN}[ EXPORTS ({len(pe.exports)}) ]{Colors.RESET}
{Colors.DIM}{'─' * 50}{Colors.RESET}""")
    if pe.exports:
        for exp in pe.exports[:15]:
            print(f"  {Colors.YELLOW}{exp.ordinal:4d}{Colors.RESET}  {Colors.CYAN}{exp.name}{Colors.RESET}")
    else:
        print(f"  {Colors.DIM}No exports found{Colors.RESET}")
    
    print(f"""
{Colors.CYAN}[ STRINGS ({len(pe.strings)}) ]{Colors.RESET}
{Colors.DIM}{'─' * 50}{Colors.RESET}""")
    for s in pe.strings[:20]:
        s_display = s[:60] + '...' if len(s) > 60 else s
        print(f"  {Colors.GREEN}{s_display}{Colors.RESET}")
    
    if pe.suspicious:
        print(f"""
{Colors.RED}[ SUSPICIOUS ({len(pe.suspicious)}) ]{Colors.RESET}
{Colors.DIM}{'─' * 50}{Colors.RESET}""")
        for sus in pe.suspicious[:10]:
            sev = f"{Colors.RED}HIGH{Colors.RESET}" if sus['severity'] == 'HIGH' else f"{Colors.YELLOW}MEDIUM{Colors.RESET}"
            print(f"  {sev} {Colors.DIM}[{sus['category']}]{Colors.RESET} {sus['string'][:50]}")
    
    print(f"""
{Colors.DIM}{'─' * 50}
  Analysis complete. {len(pe.suspicious)} suspicious items found.
{Colors.RESET}""")
    return 0


def cmd_strings(args):
    """Extract strings from PE"""
    pe = PEAnalyzer(args.file)
    if not pe.load() or not pe.parse_pe():
        print(f"{Colors.RED}[!] Invalid PE file{Colors.RESET}")
        return 1
        
    pe.extract_strings(min_len=args.min_length)
    
    print(f"{Colors.CYAN}[ STRINGS ({len(pe.strings)} found) ]{Colors.RESET}\n")
    
    for s in pe.strings:
        if args.filter:
            if not re.search(args.filter, s, re.IGNORECASE):
                continue
        print(f"  {Colors.GREEN}{s}{Colors.RESET}")
    return 0


def cmd_hash(args):
    """Calculate hashes"""
    pe = PEAnalyzer(args.file)
    if not pe.load():
        return 1
        
    print(f"{Colors.CYAN}[ HASHES for {pe.filename} ]{Colors.RESET}\n")
    
    hashes = {
        'MD5': hashlib.md5(pe.data).hexdigest(),
        'SHA1': hashlib.sha1(pe.data).hexdigest(),
        'SHA256': hashlib.sha256(pe.data).hexdigest(),
        'SHA512': hashlib.sha512(pe.data).hexdigest(),
    }
    
    for algo, h in hashes.items():
        print(f"  {Colors.WHITE}{algo:<8}{Colors.RESET} {Colors.YELLOW}{h}{Colors.RESET}")
    return 0


def cmd_headers(args):
    """View PE headers"""
    pe = PEAnalyzer(args.file)
    if not pe.load() or not pe.parse_pe():
        print(f"{Colors.RED}[!] Invalid PE file{Colors.RESET}")
        return 1
        
    print(f"{Colors.CYAN}[ DOS HEADER ]{Colors.RESET}")
    print(f"  Magic:          MZ (0x5A4D)")
    print(f"  PE Offset:      0x{pe.pe_offset:X}")
    
    print(f"\n{Colors.CYAN}[ FILE HEADER ]{Colors.RESET}")
    machine_map = {0x14c: 'I386', 0x8664: 'AMD64', 0x1c0: 'ARM', 0xaa64: 'ARM64'}
    print(f"  Machine:         {machine_map.get(pe.file_header['machine'], 'Unknown')}")
    print(f"  Number of Sections: {pe.file_header['num_sections']}")
    print(f"  Timestamp:       {datetime.fromtimestamp(pe.file_header['timestamp']).strftime('%Y-%m-%d %H:%M:%S')}")
    
    print(f"\n{Colors.CYAN}[ OPTIONAL HEADER ]{Colors.RESET}")
    magic = "PE32" if pe.optional_header['magic'] == 0x10b else "PE32+"
    print(f"  Magic:           {magic}")
    print(f"  Entry Point:     0x{pe.optional_header['entry_point']:08X}")
    print(f"  Image Base:      0x{pe.optional_header['image_base']:X}")
    print(f"  Linker Version:  {pe.optional_header['linker_ver']}")
    return 0


def cmd_sections(args):
    """Analyze sections"""
    pe = PEAnalyzer(args.file)
    if not pe.load() or not pe.parse_pe():
        print(f"{Colors.RED}[!] Invalid PE file{Colors.RESET}")
        return 1
        
    print(f"{Colors.CYAN}[ SECTIONS ({len(pe.sections)}) ]{Colors.RESET}\n")
    print(f"  {Colors.WHITE}{'Name':<10} {'VirtAddr':<12} {'VirtSize':<10} {'RawSize':<10} {'RawOff':<10} {'Entropy':<8} Flags{Colors.RESET}")
    print(f"  {Colors.DIM}{'─' * 75}{Colors.RESET}")
    
    for s in pe.sections:
        ent_color = Colors.GREEN if s.entropy < 5 else Colors.YELLOW if s.entropy < 7 else Colors.RED
        flag_str = ' '.join(s.flags) if s.flags else '-'
        print(f"  {Colors.WHITE}{s.name:<10}{Colors.RESET} "
              f"{Colors.CYAN}0x{s.virtual_address:08X}{Colors.RESET} "
              f"{Colors.CYAN}0x{s.virtual_size:08X}{Colors.RESET} "
              f"{Colors.CYAN}0x{s.raw_size:08X}{Colors.RESET} "
              f"{Colors.CYAN}0x{s.raw_offset:08X}{Colors.RESET} "
              f"{ent_color}{s.entropy:>6.2f}{Colors.RESET}  "
              f"{Colors.DIM}{flag_str}{Colors.RESET}")
    
    print(f"\n{Colors.DIM}[ High entropy (>6.5) may indicate packing ]{Colors.RESET}")
    return 0


def cmd_imports(args):
    """List imports and exports"""
    pe = PEAnalyzer(args.file)
    if not pe.load() or not pe.parse_pe():
        print(f"{Colors.RED}[!] Invalid PE file{Colors.RESET}")
        return 1
        
    pe.parse_imports()
    pe.parse_exports()
    
    print(f"{Colors.CYAN}[ IMPORTS ({len(pe.imports)} DLLs) ]{Colors.RESET}\n")
    if pe.imports:
        for imp in pe.imports:
            print(f"  {Colors.GREEN}{imp.dll}{Colors.RESET}")
            for f in imp.functions:
                print(f"    └── {Colors.YELLOW}{f}{Colors.RESET}")
    else:
        print(f"  {Colors.DIM}No imports{Colors.RESET}")
    
    print(f"\n{Colors.CYAN}[ EXPORTS ({len(pe.exports)}) ]{Colors.RESET}\n")
    if pe.exports:
        for exp in pe.exports:
            print(f"  {Colors.YELLOW}{exp.ordinal:4d}{Colors.RESET}  {Colors.CYAN}{exp.name}{Colors.RESET}")
    else:
        print(f"  {Colors.DIM}No exports{Colors.RESET}")
    return 0


def cmd_compare(args):
    """Compare two PE files"""
    if not os.path.exists(args.file1) or not os.path.exists(args.file2):
        print(f"{Colors.RED}[!] One or both files not found{Colors.RESET}")
        return 1
        
    pe1 = PEAnalyzer(args.file1)
    pe2 = PEAnalyzer(args.file2)
    
    if not pe1.load() or not pe1.parse_pe():
        print(f"{Colors.RED}[!] {args.file1} is not a valid PE{Colors.RESET}")
        return 1
    if not pe2.load() or not pe2.parse_pe():
        print(f"{Colors.RED}[!] {args.file2} is not a valid PE{Colors.RESET}")
        return 1
        
    pe1.parse_imports()
    pe2.parse_imports()
    
    h1 = hashlib.sha256(pe1.data).hexdigest()
    h2 = hashlib.sha256(pe2.data).hexdigest()
    
    same_hash = h1 == h2
    same_imp1 = {i.dll for i in pe1.imports}
    same_imp2 = {i.dll for i in pe2.imports}
    
    print(f"{Colors.CYAN}[ COMPARISON: {pe1.filename} vs {pe2.filename} ]{Colors.RESET}\n")
    
    print(f"  {Colors.WHITE}Hashes:{Colors.RESET}")
    print(f"    File 1: {Colors.YELLOW}{h1[:32]}...{Colors.RESET}")
    print(f"    File 2: {Colors.YELLOW}{h2[:32]}...{Colors.RESET}")
    print(f"    Match:  {Colors.GREEN if same_hash else Colors.RED}{'YES' if same_hash else 'NO'}{Colors.RESET}")
    
    print(f"\n  {Colors.WHITE}Imports:{Colors.RESET}")
    print(f"    File 1: {len(pe1.imports)} DLLs")
    print(f"    File 2: {len(pe2.imports)} DLLs")
    
    common = same_imp1 & same_imp2
    only_1 = same_imp1 - same_imp2
    only_2 = same_imp2 - same_imp1
    
    if common:
        print(f"    {Colors.GREEN}Common:{Colors.RESET} {', '.join(sorted(common))}")
    if only_1:
        print(f"    {Colors.YELLOW}Only in {pe1.filename}:{Colors.RESET} {', '.join(sorted(only_1))}")
    if only_2:
        print(f"    {Colors.YELLOW}Only in {pe2.filename}:{Colors.RESET} {', '.join(sorted(only_2))}")
    return 0


def cmd_sig(args):
    """Check digital signature"""
    print(f"{Colors.YELLOW}[!] Signature checking requires Windows API{Colors.RESET}")
    print(f"{Colors.DIM}    This feature is limited on non-Windows systems{Colors.RESET}")
    print(f"\n{Colors.CYAN}[ SIGNATURE INFO ]{Colors.RESET}")
    print(f"  To check signatures on Windows, use:\n")
    print(f"    sigcheck.exe -h {args.file}\n")
    print(f"  Or right-click the file → Properties → Digital Signatures\n")
    return 0


def main():
    if len(sys.argv) < 2:
        print(Banner.main())
        sys.exit(0)
        
    tool = sys.argv[1].lower()
    
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('file', nargs='?')
    
    if tool == 'info':
        parser = argparse.ArgumentParser(description='Full PE analysis')
        parser.add_argument('file', help='PE file to analyze')
        parser.add_argument('-o', '--output', help='Save report to file')
        parser.add_argument('--min-length', type=int, default=4, help='Minimum string length')
        args = parser.parse_args()
        sys.exit(cmd_info(args))
        
    elif tool == 'strings':
        parser = argparse.ArgumentParser(description='Extract strings')
        parser.add_argument('file', help='PE file')
        parser.add_argument('-m', '--min-length', type=int, default=4)
        parser.add_argument('-f', '--filter', help='Regex filter')
        args = parser.parse_args()
        sys.exit(cmd_strings(args))
        
    elif tool == 'hash':
        parser = argparse.ArgumentParser(description='Calculate hashes')
        parser.add_argument('file', help='File to hash')
        args = parser.parse_args()
        sys.exit(cmd_hash(args))
        
    elif tool == 'headers':
        parser = argparse.ArgumentParser(description='View PE headers')
        parser.add_argument('file', help='PE file')
        args = parser.parse_args()
        sys.exit(cmd_headers(args))
        
    elif tool == 'sections':
        parser = argparse.ArgumentParser(description='Analyze sections')
        parser.add_argument('file', help='PE file')
        args = parser.parse_args()
        sys.exit(cmd_sections(args))
        
    elif tool == 'imports':
        parser = argparse.ArgumentParser(description='List imports/exports')
        parser.add_argument('file', help='PE file')
        args = parser.parse_args()
        sys.exit(cmd_imports(args))
        
    elif tool == 'compare':
        parser = argparse.ArgumentParser(description='Compare two PE files')
        parser.add_argument('file1', help='First PE file')
        parser.add_argument('file2', help='Second PE file')
        args = parser.parse_args()
        sys.exit(cmd_compare(args))
        
    elif tool == 'sig':
        parser = argparse.ArgumentParser(description='Check digital signature')
        parser.add_argument('file', help='PE file')
        args = parser.parse_args()
        sys.exit(cmd_sig(args))
        
    elif tool in ['-h', '--help', 'help']:
        print(Banner.main())
        sys.exit(0)
        
    else:
        print(Banner.main())
        print(f"{Colors.RED}[!] Unknown tool: {tool}{Colors.RESET}")
        sys.exit(1)


if __name__ == '__main__':
    main()
