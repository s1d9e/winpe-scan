#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║                      WINPE-SCAN v1.0                          ║
║           ╔═══════════════════════════════════════╗            ║
║           ║   "Knowledge is power, but analysis  ║            ║
║           ║    is understanding..."              ║            ║
║           ╚═══════════════════════════════════════╝            ║
╚══════════════════════════════════════════════════════════════════╝

Windows PE (Portable Executable) Analyzer
Analyze PE files for malware analysis and security research.

[!] FOR EDUCATIONAL PURPOSES ONLY
"""

import struct
import os
import sys
import hashlib
import argparse
from datetime import datetime
from enum import Enum
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
import re

class SectionFlags(Enum):
    IMAGE_SCN_CNT_CODE = 0x00000020
    IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
    IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
    IMAGE_SCN_MEM_EXECUTE = 0x20000000
    IMAGE_SCN_MEM_READ = 0x40000000
    IMAGE_SCN_MEM_WRITE = 0x80000000

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
class ResourceEntry:
    type: str
    name: str
    offset: int
    size: int
    language: str

class PEAnalyzer:
    """PE File Analyzer"""
    
    # Known suspicious strings patterns
    SUSPICIOUS_PATTERNS = {
        "network": [
            r'https?://[^\s]+\.[a-z]{2,}',
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
            r'socket|connect|send|recv|listen',
            r'HttpSendRequest|WinHttp|PowerShell',
        ],
        "command": [
            r'cmd\.exe|command\.com|powershell',
            r'/c\s+\w+|/k\s+\w+',
            r'CreateProcess|ShellExecute',
        ],
        "crypto": [
            r'CryptEncrypt|CryptDecrypt',
            r'MD5|SHA1|SHA256',
            r'Base64Decode|Base64Encode',
        ],
        "registry": [
            r'RegOpenKey|RegSetValue|RegCreateKey',
            r'SOFTWARE\\|SYSTEM\\',
        ],
        "mutex": [
            r'Mutex|CreateMutex|OpenMutex',
        ],
        "services": [
            r'CreateService|StartService|StopService',
            r'ServiceMain|ControlHandler',
        ]
    }
    
    # Known DLLs
    COMMON_DLLS = [
        "kernel32.dll", "ntdll.dll", "user32.dll", "gdi32.dll",
        "advapi32.dll", "ws2_32.dll", "wininet.dll", "urlmon.dll",
        "shlwapi.dll", "shell32.dll", "ole32.dll", "oleaut32.dll",
        "msvcrt.dll", "msvcrtd.dll", "comctl32.dll", "comdlg32.dll",
        "version.dll", "setupapi.dll", "winspool.drv", "crypt32.dll",
        "imagehlp.dll", "rsaenh.dll", "secur32.dll", "netapi32.dll",
        "iphlpapi.dll", "dnsapi.dll", "dhcpcsvc.dll", "cryptsp.dll",
        "rasapi32.dll", "winhttp.dll", "sensapi.dll", "sysinfodata.dll",
    ]
    
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.filename = os.path.basename(filepath)
        self.data = None
        self.file_size = 0
        self.is_valid_pe = False
        
        # PE Headers
        self.dos_header = None
        self.pe_offset = 0
        self.nt_headers = None
        self.file_header = None
        self.optional_header = None
        
        # Analysis results
        self.sections: List[PESection] = []
        self.imports: List[ImportEntry] = []
        self.exports: List[ExportEntry] = []
        self.resources: List[ResourceEntry] = []
        self.strings: List[str] = []
        self.hashes: Dict[str, str] = {}
        self.suspicious: List[Dict] = []
        
    def load_file(self) -> bool:
        """Load the PE file"""
        try:
            with open(self.filepath, 'rb') as f:
                self.data = f.read()
            self.file_size = len(self.data)
            return True
        except Exception as e:
            print(f"[!] Error loading file: {e}")
            return False
            
    def calculate_hashes(self):
        """Calculate file hashes"""
        self.hashes = {
            'MD5': hashlib.md5(self.data).hexdigest(),
            'SHA1': hashlib.sha1(self.data).hexdigest(),
            'SHA256': hashlib.sha256(self.data).hexdigest(),
        }
        
    def parse_dos_header(self) -> bool:
        """Parse DOS header"""
        if len(self.data) < 64:
            return False
            
        magic = struct.unpack('<H', self.data[0:2])[0]
        if magic != 0x5A4D:  # 'MZ'
            return False
            
        self.dos_header = {
            'magic': 'MZ',
            'header_size': struct.unpack('<H', self.data[60:62])[0],
        }
        
        self.pe_offset = struct.unpack('<I', self.data[60:64])[0]
        return True
        
    def parse_pe_headers(self) -> bool:
        """Parse PE and NT headers"""
        if self.pe_offset >= len(self.data) - 4:
            return False
            
        signature = self.data[self.pe_offset:self.pe_offset+4]
        if signature != b'PE\x00\x00':
            return False
            
        self.is_valid_pe = True
        
        # File Header
        offset = self.pe_offset + 4
        self.file_header = {
            'machine': struct.unpack('<H', self.data[offset:offset+2])[0],
            'number_of_sections': struct.unpack('<H', self.data[offset+2:offset+4])[0],
            'timestamp': struct.unpack('<I', self.data[offset+4:offset+8])[0],
            'pointer_to_symbols': struct.unpack('<I', self.data[offset+8:offset+12])[0],
            'number_of_symbols': struct.unpack('<I', self.data[offset+12:offset+16])[0],
            'optional_header_size': struct.unpack('<H', self.data[offset+16:offset+18])[0],
            'characteristics': struct.unpack('<H', self.data[offset+18:offset+20])[0],
        }
        
        # Optional Header
        opt_offset = offset + 20
        self.optional_header = {
            'magic': struct.unpack('<H', self.data[opt_offset:opt_offset+2])[0],
            'linker_version': f"{self.data[opt_offset+2]}.{self.data[opt_offset+3]}",
            'size_of_code': struct.unpack('<I', self.data[opt_offset+4:opt_offset+8])[0],
            'size_of_initialized_data': struct.unpack('<I', self.data[opt_offset+8:opt_offset+12])[0],
            'entry_point': struct.unpack('<I', self.data[opt_offset+16:opt_offset+20])[0],
            'base_of_code': struct.unpack('<I', self.data[opt_offset+20:opt_offset+24])[0],
        }
        
        if self.optional_header['magic'] == 0x10b:
            self.optional_header['image_base'] = struct.unpack('<I', self.data[opt_offset+28:opt_offset+32])[0]
            self.optional_header['section_alignment'] = struct.unpack('<I', self.data[opt_offset+32:opt_offset+36])[0]
            self.optional_header['file_alignment'] = struct.unpack('<I', self.data[opt_offset+36:opt_offset+40])[0]
            self.optional_header['os_version'] = f"{struct.unpack('<H', self.data[opt_offset+40:opt_offset+42])[0]}.{struct.unpack('<H', self.data[opt_offset+42:opt_offset+44])[0]}"
            self.optional_header['subsystem'] = struct.unpack('<H', self.data[opt_offset+68:opt_offset+70])[0]
        elif self.optional_header['magic'] == 0x20b:
            self.optional_header['image_base'] = struct.unpack('<Q', self.data[opt_offset+24:opt_offset+32])[0]
            self.optional_header['subsystem'] = struct.unpack('<H', self.data[opt_offset+88:opt_offset+90])[0]
            
        return True
        
    def parse_sections(self):
        """Parse section headers"""
        if not self.file_header or not self.optional_header:
            return
            
        section_offset = self.pe_offset + 4 + 20 + self.file_header['optional_header_size']
        
        for i in range(self.file_header['number_of_sections']):
            offset = section_offset + (i * 40)
            if offset + 40 > len(self.data):
                break
                
            name_bytes = self.data[offset:offset+8].rstrip(b'\x00')
            name = name_bytes.decode('ascii', errors='ignore') if name_bytes else ''
            
            virtual_size = struct.unpack('<I', self.data[offset+8:offset+12])[0]
            virtual_address = struct.unpack('<I', self.data[offset+12:offset+16])[0]
            raw_size = struct.unpack('<I', self.data[offset+16:offset+20])[0]
            raw_offset = struct.unpack('<I', self.data[offset+20:offset+24])[0]
            characteristics = struct.unpack('<I', self.data[offset+36:offset+40])[0]
            
            flags = []
            if characteristics & 0x20000000: flags.append('EXEC')
            if characteristics & 0x40000000: flags.append('READ')
            if characteristics & 0x80000000: flags.append('WRITE')
            if characteristics & 0x20: flags.append('CODE')
            if characteristics & 0x40: flags.append('INIT')
            
            entropy = self.calculate_entropy(raw_offset, raw_size)
            
            self.sections.append(PESection(
                name=name,
                virtual_address=virtual_address,
                virtual_size=virtual_size,
                raw_size=raw_size,
                raw_offset=raw_offset,
                entropy=entropy,
                flags=flags
            ))
            
    def calculate_entropy(self, offset: int, size: int) -> float:
        """Calculate section entropy"""
        if size == 0 or offset + size > len(self.data):
            return 0.0
            
        section_data = self.data[offset:offset+size]
        if len(section_data) == 0:
            return 0.0
            
        entropy = 0
        byte_counts = [0] * 256
        
        for byte in section_data:
            byte_counts[byte] += 1
            
        for count in byte_counts:
            if count == 0:
                continue
            probability = count / len(section_data)
            entropy -= probability * (probability.bit_length() - 1 if probability < 1 else 0)
            entropy -= probability * (probability.bit_length())
            
        for count in byte_counts:
            if count == 0:
                continue
            probability = count / len(section_data)
            entropy -= probability * (probability.bit_length())
            
        return round(abs(entropy), 2)
        
    def parse_imports(self):
        """Parse import table"""
        if not self.optional_header or self.optional_header['magic'] != 0x10b:
            return
            
        opt_offset = self.pe_offset + 4 + 20
        
        import_table_rva = 0
        try:
            import_table_rva = struct.unpack('<I', self.data[opt_offset+104:opt_offset+108])[0]
        except:
            return
            
        if import_table_rva == 0:
            return
            
        import_offset = self.rva_to_offset(import_table_rva)
        if import_offset == 0 or import_offset >= len(self.data):
            return
            
        offset = import_offset
        seen_dlls = set()
        
        while True:
            if offset + 20 > len(self.data):
                break
                
            ilt_rva = struct.unpack('<I', self.data[offset:offset+4])[0]
            timestamp = struct.unpack('<I', self.data[offset+4:offset+8])[0]
            forwarder = struct.unpack('<I', self.data[offset+8:offset+12])[0]
            name_rva = struct.unpack('<I', self.data[offset+12:offset+16])[0]
            ilt_offset = self.rva_to_offset(ilt_rva)
            
            if name_rva == 0:
                break
                
            name_offset = self.rva_to_offset(name_rva)
            if name_offset > 0 and name_offset < len(self.data):
                dll_name = self.read_string(name_offset).lower()
                
                if dll_name and dll_name not in seen_dlls:
                    seen_dlls.add(dll_name)
                    functions = []
                    
                    func_offset = ilt_offset
                    while func_offset + 4 <= len(self.data):
                        func_rva = struct.unpack('<I', self.data[func_offset:func_offset+4])[0]
                        if func_rva == 0:
                            break
                        if func_rva & 0x80000000:
                            functions.append(f"Ordinal #{func_rva & 0x7FFFFFFF}")
                        else:
                            func_name_offset = self.rva_to_offset(func_rva + 2)
                            if func_name_offset > 0:
                                func_name = self.read_string(func_name_offset)
                                if func_name:
                                    functions.append(func_name)
                        func_offset += 4
                        
                    self.imports.append(ImportEntry(dll=dll_name, functions=functions))
                    
            offset += 20
            
    def parse_exports(self):
        """Parse export table"""
        if not self.optional_header or self.optional_header['magic'] != 0x10b:
            return
            
        opt_offset = self.pe_offset + 4 + 20
        
        try:
            export_rva = struct.unpack('<I', self.data[opt_offset+96:opt_offset+100])[0]
        except:
            return
            
        if export_rva == 0:
            return
            
        export_offset = self.rva_to_offset(export_rva)
        if export_offset == 0 or export_offset + 24 > len(self.data):
            return
            
        num_functions = struct.unpack('<I', self.data[export_offset+20:export_offset+24])[0]
        num_names = struct.unpack('<I', self.data[export_offset+24:export_offset+28])[0]
        func_addr_rva = struct.unpack('<I', self.data[export_offset+28:export_offset+32])[0]
        name_rva = struct.unpack('<I', self.data[export_offset+32:export_offset+36])[0]
        ordinal_base = struct.unpack('<I', self.data[export_offset+36:export_offset+40])[0]
        
        for i in range(min(num_names, 100)):
            try:
                name_offset = self.rva_to_offset(struct.unpack('<I', self.data[name_rva + i*4:name_rva + i*4 + 4])[0])
                if name_offset > 0:
                    name = self.read_string(name_offset)
                    if name:
                        addr_offset = self.rva_to_offset(struct.unpack('<I', self.data[func_addr_rva + i*4:func_addr_rva + i*4 + 4])[0])
                        self.exports.append(ExportEntry(
                            ordinal=ordinal_base + i,
                            name=name,
                            address=addr_offset
                        ))
            except:
                break
                
    def extract_strings(self, min_length=4):
        """Extract ASCII and Unicode strings"""
        patterns = [
            (b'[\x20-\x7e]{' + str(min_length).encode() + b',}', 'ascii'),
            (b'(?:[\x20-\x7e]\x00){' + str(min_length).encode() + b',}', 'unicode'),
        ]
        
        strings_set = set()
        
        for pattern, encoding in patterns:
            for match in re.finditer(pattern, self.data):
                s = match.group(0)
                if encoding == 'unicode':
                    s = s.decode('utf-16-le', errors='ignore')
                else:
                    s = s.decode('ascii', errors='ignore')
                    
                if len(s) >= min_length:
                    strings_set.add(s)
                    
        self.strings = sorted(strings_set, key=len, reverse=True)
        
    def detect_suspicious(self):
        """Detect suspicious patterns in strings"""
        for category, patterns in self.SUSPICIOUS_PATTERNS.items():
            for pattern in patterns:
                for s in self.strings:
                    if re.search(pattern, s, re.IGNORECASE):
                        self.suspicious.append({
                            'category': category.upper(),
                            'pattern': pattern,
                            'string': s[:100],
                            'severity': 'HIGH' if category in ['command', 'crypto'] else 'MEDIUM'
                        })
                        
    def rva_to_offset(self, rva: int) -> int:
        """Convert RVA to file offset"""
        for section in self.sections:
            if (section.virtual_address <= rva < 
                section.virtual_address + section.virtual_size):
                return rva - section.virtual_address + section.raw_offset
        return 0
        
    def read_string(self, offset: int, max_len=256) -> str:
        """Read null-terminated string"""
        if offset >= len(self.data):
            return ""
        end = offset
        while end < len(self.data) and end < offset + max_len:
            if self.data[end] == 0:
                break
            end += 1
        return self.data[offset:end].decode('ascii', errors='ignore')
        
    def analyze(self):
        """Run full analysis"""
        if not self.load_file():
            return False
            
        self.calculate_hashes()
        
        if not self.parse_dos_header():
            return False
            
        if not self.parse_pe_headers():
            return False
            
        self.parse_sections()
        self.parse_imports()
        self.parse_exports()
        self.extract_strings()
        self.detect_suspicious()
        
        return True
        
    def generate_report(self) -> str:
        """Generate analysis report"""
        if not self.is_valid_pe:
            return "[!] Invalid or non-PE file"
            
        report = []
        report.append(self._header())
        report.append(self._basic_info())
        report.append(self._headers_section())
        report.append(self._sections_section())
        report.append(self._imports_section())
        report.append(self._exports_section())
        report.append(self._strings_section())
        report.append(self._suspicious_section())
        report.append(self._footer())
        
        return '\n'.join(report)
        
    def _header(self) -> str:
        return f"""
\033[91m╔{'═' * 66}╗\033[0m
\033[91m║\033[0m{' ' * 17}\033[93mWINPE-SCAN v1.0\033[0m{' ' * 27}\033[91m║\033[0m
\033[91m║\033[0m{' ' * 10}\033[93mWindows PE File Analyzer\033[0m{' ' * 36}\033[91m║\033[0m
\033[91m╚{'═' * 66}╝\033[0m"""
        
    def _basic_info(self) -> str:
        lines = [
            "",
            "\033[93m[\033[0m\033[1m BASIC INFO \033[0m\033[93m]\033[0m",
            "\033[90m" + "─" * 50 + "\033[0m",
            f"  File:     \033[96m{self.filename}\033[0m",
            f"  Size:     \033[96m{self.file_size:,} bytes\033[0m ({self.file_size / 1024:.2f} KB)",
            f"  MD5:      \033[93m{self.hashes.get('MD5', 'N/A')}\033[0m",
            f"  SHA256:   \033[93m{self.hashes.get('SHA256', 'N/A')[:32]}...\033[0m",
        ]
        return '\n'.join(lines)
        
    def _headers_section(self) -> str:
        machine_map = {0x14c: 'x86', 0x8664: 'x64', 0x1c0: 'ARM', 0xaa64: 'ARM64'}
        subsystem_map = {1: 'Native', 2: 'Windows GUI', 3: 'Windows CUI', 7: 'POSIX'}
        
        machine = machine_map.get(self.file_header.get('machine', 0), 'Unknown')
        subsystem = subsystem_map.get(self.optional_header.get('subsystem', 0), 'Unknown')
        
        timestamp = self.file_header.get('timestamp', 0)
        try:
            dt = datetime.fromtimestamp(timestamp)
            date_str = dt.strftime('%Y-%m-%d %H:%M:%S')
        except:
            date_str = 'Unknown'
            
        lines = [
            "",
            "\033[93m[\033[0m\033[1m PE HEADERS \033[0m\033[93m]\033[0m",
            "\033[90m" + "─" * 50 + "\033[0m",
            f"  Machine:      \033[96m{machine}\033[0m",
            f"  Sections:      \033[96m{self.file_header.get('number_of_sections', 0)}\033[0m",
            f"  Subsystem:     \033[96m{subsystem}\033[0m",
            f"  Entry Point:  \033[96m0x{self.optional_header.get('entry_point', 0):08X}\033[0m",
            f"  Image Base:    \033[96m0x{self.optional_header.get('image_base', 0):X}\033[0m",
            f"  Timestamp:     \033[96m{date_str}\033[0m",
            f"  Linker Ver:    \033[96m{self.optional_header.get('linker_version', 'N/A')}\033[0m",
            f"  OS Version:    \033[96m{self.optional_header.get('os_version', 'N/A')}\033[0m",
        ]
        return '\n'.join(lines)
        
    def _sections_section(self) -> str:
        lines = [
            "",
            "\033[93m[\033[0m\033[1m SECTIONS \033[0m\033[93m]\033[0m",
            "\033[90m" + "─" * 50 + "\033[0m",
            f"  {'Name':<10} {'VirtAddr':<12} {'VirtSize':<10} {'RawSize':<10} {'Entropy':<8} Flags",
            "\033[90m" + "─" * 50 + "\033[0m",
        ]
        
        for sec in self.sections:
            entropy_color = '\033[92m' if sec.entropy < 5 else '\033[93m' if sec.entropy < 7 else '\033[91m'
            lines.append(
                f"  {sec.name:<10} "
                f"\033[96m0x{sec.virtual_address:08X}\033[0m "
                f"\033[96m0x{sec.virtual_size:08X}\033[0m "
                f"\033[96m0x{sec.raw_size:08X}\033[0m "
                f"{entropy_color}{sec.entropy:<8.2f}\033[0m "
                f"\033[90m{' '.join(sec.flags)}\033[0m"
            )
            
        return '\n'.join(lines)
        
    def _imports_section(self) -> str:
        lines = [
            "",
            "\033[93m[\033[0m\033[1m IMPORTS \033[0m\033[93m]\033[0m",
            "\033[90m" + "─" * 50 + "\033[0m",
        ]
        
        if not self.imports:
            lines.append("  \033[90mNo imports found\033[0m")
        else:
            for imp in self.imports[:20]:
                dll_name = imp.dll.replace('.dll', '')
                funcs = ', '.join(imp.functions[:10])
                if len(imp.functions) > 10:
                    funcs += f" \033[90m...+{len(imp.functions)-10} more\033[0m"
                lines.append(f"  \033[96m{dll_name}\033[0m.dll → {funcs}")
                
        return '\n'.join(lines)
        
    def _exports_section(self) -> str:
        lines = [
            "",
            "\033[93m[\033[0m\033[1m EXPORTS \033[0m\033[93m]\033[0m",
            "\033[90m" + "─" * 50 + "\033[0m",
        ]
        
        if not self.exports:
            lines.append("  \033[90mNo exports found\033[0m")
        else:
            for exp in self.exports[:20]:
                lines.append(f"  \033[96m{exp.ordinal:4d}\033[0m 0x{exp.address:08X} \033[93m{exp.name}\033[0m")
                
        return '\n'.join(lines)
        
    def _strings_section(self) -> str:
        lines = [
            "",
            "\033[93m[\033[0m\033[1m STRINGS \033[0m\033[93m]\033[0m",
            "\033[90m" + "─" * 50 + "\033[0m",
            f"  Total strings found: \033[96m{len(self.strings)}\033[0m",
            "\033[90m" + "─" * 50 + "\033[0m",
        ]
        
        interesting = [s for s in self.strings if len(s) > 10][:30]
        for s in interesting:
            s_display = s[:60] + '...' if len(s) > 60 else s
            lines.append(f"  \033[92m{s_display}\033[0m")
            
        return '\n'.join(lines)
        
    def _suspicious_section(self) -> str:
        lines = [
            "",
            "\033[91m[\033[0m\033[1m SUSPICIOUS PATTERNS \033[0m\033[91m]\033[0m",
            "\033[90m" + "─" * 50 + "\033[0m",
        ]
        
        if not self.suspicious:
            lines.append("  \033[92mNo suspicious patterns detected\033[0m")
        else:
            for sus in self.suspicious[:15]:
                sev = '\033[91mHIGH\033[0m' if sus['severity'] == 'HIGH' else '\033[93mMEDIUM\033[0m'
                lines.append(f"  {sev} \033[90m[\033[0m{sus['category']}\033[90m]\033[0m {sus['string'][:45]}")
                
        return '\n'.join(lines)
        
    def _footer(self) -> str:
        return f"""
\033[90m{'─' * 50}\033[0m
  Analysis complete. Found \033[93m{len(self.suspicious)}\033[0m suspicious items.
  \033[90mGenerated by WinPE-Scan v1.0\033[0m
"""


def main():
    parser = argparse.ArgumentParser(
        description='WinPE-Scan - Windows PE File Analyzer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 winpe-scan.py malware.exe
  python3 winpe-scan.py -o report.txt sample.dll
  python3 winpe-scan.py --json analysis.json suspicious.exe
        """
    )
    
    parser.add_argument('file', help='PE file to analyze')
    parser.add_argument('-o', '--output', help='Save report to file')
    parser.add_argument('--json', action='store_true', help='Output in JSON format')
    parser.add_argument('--strings', action='store_true', help='Show only strings')
    parser.add_argument('--no-color', action='store_true', help='Disable colors')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.file):
        print(f"[!] File not found: {args.file}")
        sys.exit(1)
        
    analyzer = PEAnalyzer(args.file)
    
    print(f"[*] Analyzing {args.file}...", file=sys.stderr)
    
    if not analyzer.analyze():
        print("[!] Failed to analyze file. Is it a valid PE file?")
        sys.exit(1)
        
    if args.json:
        import json
        output = {
            'filename': analyzer.filename,
            'size': analyzer.file_size,
            'hashes': analyzer.hashes,
            'sections': [
                {
                    'name': s.name,
                    'virtual_address': hex(s.virtual_address),
                    'virtual_size': hex(s.virtual_size),
                    'entropy': s.entropy,
                    'flags': s.flags
                }
                for s in analyzer.sections
            ],
            'imports': [
                {'dll': i.dll, 'functions': i.functions}
                for i in analyzer.imports
            ],
            'exports': [
                {'ordinal': e.ordinal, 'name': e.name}
                for e in analyzer.exports
            ],
            'strings': analyzer.strings[:100],
            'suspicious': analyzer.suspicious
        }
        print(json.dumps(output, indent=2))
    else:
        report = analyzer.generate_report()
        
        if args.output:
            with open(args.output, 'w') as f:
                import re
                clean_report = re.sub(r'\x1b\[[0-9;]*m', '', report)
                f.write(clean_report)
            print(f"[*] Report saved to {args.output}")
        else:
            print(report)


if __name__ == '__main__':
    main()
