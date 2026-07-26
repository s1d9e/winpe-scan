"""
Data models for PE analysis results.

Copyright (c) 2026 s1d9e - MIT License
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(Enum):
    """Threat severity levels."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RiskLevel(Enum):
    """Overall risk classification."""

    CLEAN = "CLEAN"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


MACHINE_TYPES: dict[int, str] = {
    0x014C: "I386",
    0x0200: "IA64",
    0x8664: "AMD64",
    0x01C0: "ARM",
    0x01C4: "ARMNT",
    0xAA64: "ARM64",
}

SUBSYSTEM_TYPES: dict[int, str] = {
    0: "Unknown",
    1: "Native",
    2: "Windows GUI",
    3: "Windows CUI",
    5: "OS/2 CUI",
    7: "POSIX CUI",
    9: "Windows CE GUI",
    10: "EFI Application",
    11: "EFI Boot Service Driver",
    12: "EFI Runtime Driver",
    13: "EFI ROM",
    14: "Xbox",
    16: "Windows Boot Application",
}

PACKER_SIGNATURES: dict[str, dict[str, object]] = {
    "UPX": {
        "section_names": {".UPX0", ".UPX1", ".UPX2"},
        "imports": {"UPX0", "UPX1", "UPX2"},
        "ep_bytes": b"UPX!",
    },
    "ASPack": {
        "section_names": {".aspack", ".adata"},
        "ep_bytes": b"\xEB\x05\xE8\x00\x00\x00\x00",
    },
    "PECompact": {"section_names": {".PEC2", ".PEC2MO", ".pec1", ".pec2"}},
    "Themida": {"section_names": {".Themida", ".winlice"}},
    "VMProtect": {"section_names": {".vmp0", ".vmp1", ".vmp2"}},
    "Obsidium": {"section_names": {".obsidium"}},
    "Enigma Protector": {"section_names": {".enigma1", ".enigma2"}},
    "MEW": {"section_names": {".MEW"}},
    "FSG": {"section_names": {".FSG"}},
    "MPRESS": {"section_names": {".MPRESS1", ".MPRESS2"}},
}

SUSPICIOUS_DLLS: dict[str, str] = {
    "ws2_32.dll": "Winsock2 - network communication",
    "wininet.dll": "Windows Internet API - HTTP/FTP",
    "urlmon.dll": "URL Moniker - URL download",
    "winhttp.dll": "WinHTTP - HTTP requests",
    "shell32.dll": "Shell API - process/file operations",
    "shlwapi.dll": "Shell Lightweight Utilities",
    "advapi32.dll": "Advanced Windows - registry/services",
    "secur32.dll": "Security Support Provider",
    "crypt32.dll": "Crypto API - encryption/hashing",
    "wldap32.dll": "LDAP client",
    "netapi32.dll": "Network Management",
    "samcli.dll": "SAM Client",
    "iphlpapi.dll": "IP Helper - network info",
    "icmp.dll": "ICMP - ping/scanning",
    "dbghelp.dll": "Debug Help - anti-debug possible",
    "psapi.dll": "Process Status API - process enumeration",
    "toolhelp32.dll": "Tool Help - process snapshots",
    "ntdll.dll": "NT Layer - low-level operations",
}

ANTI_DEBUG_APIS: dict[str, str] = {
    "IsDebuggerPresent": "Checks if a debugger is attached",
    "CheckRemoteDebuggerPresent": "Checks for remote debugger",
    "NtQueryInformationProcess": "Query process debug port",
    "OutputDebugStringA": "Anti-debug via debug string",
    "OutputDebugStringW": "Anti-debug via debug string (W)",
    "SetUnhandledExceptionFilter": "Exception-based anti-debug",
    "NtSetInformationThread": "Hide thread from debugger",
    "ZwQueryInformationProcess": "Ntdll query process info",
    "GetTickCount": "Timing-based anti-debug",
    "QueryPerformanceCounter": "High-precision timing check",
    "NtQuerySystemInformation": "System information leak",
    "NtClose": "Invalid handle exception check",
    "CloseHandle": "Invalid handle exception check",
}

ANTI_VM_APIS: dict[str, str] = {
    "cpuid": "CPUID instruction - VM detection",
    "NtQuerySystemInformation": "System info - VM detection",
    "GetExtendedCpuInfo": "CPU info - VM detection",
    "SetupDiGetDevicePropertyW": "Device enumeration - VM check",
}

PROCESS_INJECTION_APIS: dict[str, str] = {
    "VirtualAllocEx": "Allocate memory in remote process",
    "WriteProcessMemory": "Write to remote process memory",
    "CreateRemoteThread": "Create thread in remote process",
    "NtCreateThreadEx": "NT create thread in remote process",
    "RtlCreateUserThread": "Create user thread in remote process",
    "QueueUserAPC": "Queue APC to remote thread",
    "NtQueueApcThread": "NT queue APC to thread",
    "SetWindowsHookExA": "Hook injection",
    "SetWindowsHookExW": "Hook injection (W)",
    "NtMapViewOfSection": "Section mapping - process hollowing",
    "ZwMapViewOfSection": "Section mapping - process hollowing",
    "NtUnmapViewOfSection": "Unmap section - process hollowing",
    "NtWriteVirtualMemory": "Write to virtual memory",
    "RtlMoveMemory": "Memory copy - shellcode staging",
}

PRIVILEGE_ESCALATION_APIS: dict[str, str] = {
    "OpenProcessToken": "Open process token",
    "AdjustTokenPrivileges": "Modify token privileges",
    "LookupPrivilegeValueA": "Look up privilege value",
    "LookupPrivilegeValueW": "Look up privilege value (W)",
    "CreateServiceA": "Create Windows service",
    "CreateServiceW": "Create Windows service (W)",
    "StartServiceA": "Start Windows service",
    "StartServiceW": "Start Windows service (W)",
    "RegSetValueExA": "Registry persistence",
    "RegSetValueExW": "Registry persistence (W)",
}

PERSISTENCE_APIS: dict[str, str] = {
    "RegSetValueExA": "Registry key modification",
    "RegSetValueExW": "Registry key modification (W)",
    "RegCreateKeyExA": "Registry key creation",
    "RegCreateKeyExW": "Registry key creation (W)",
    "CreateServiceA": "Service-based persistence",
    "CreateServiceW": "Service-based persistence (W)",
    "RegOpenKeyExA": "Registry access",
    "RegOpenKeyExW": "Registry access (W)",
}

SUSPICIOUS_PATTERNS: dict[str, list[str]] = {
    "NETWORK": [
        r"https?://[^\s\"'>]+\.(?:com|net|org|ru|cn|tk|cc|pw|xyz|top|club|online|icu)",
        r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d{1,5})?\b",
        r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}",
        r"\\\\.pipe\\\\[a-zA-Z0-9_]+",
    ],
    "COMMAND": [
        r"cmd\.exe\s*/[ck]\s+",
        r"powershell(?:\.exe)?\s+(?:-[a-zA-Z]+(?:\s|$))+",
        r"powershell.*(?:-enc|-encodedcommand|-e)\s+",
        r"certutil\s+(?:-urlcache|-split|-f)",
        r"mshta\s+",
        r"regsvr32\s+(?:/s|/u|/i:)",
        r"wscript\.exe|cscript\.exe",
        r"bitsadmin\s+",
    ],
    "CRYPTO": [
        r"CryptEncrypt",
        r"CryptDecrypt",
        r"BCryptEncrypt",
        r"BCryptDecrypt",
        r"(?:base64|b64)(?:_encode|_decode|decode|encode)",
        r"ransom",
        r"\.encrypted",
        r"\.locked",
        r"\.crypto",
        r"bitcoin|monero|ethereum|wallet",
    ],
    "OBFUSCATION": [
        r"VirtualAlloc\b",
        r"RtlMoveMemory",
        r"NtWriteVirtualMemory",
        r"(?:chr|wchr)\s*\(",
        r"(?:eval|exec)\s*\(",
        r"from_base64|to_base64",
        r"\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){7,}",
    ],
    "DATA_EXFILTRATION": [
        r"InternetOpen(?:A|W)",
        r"InternetConnect(?:A|W)",
        r"HttpSendRequest(?:A|W)",
        r"URLDownloadToFile(?:A|W)",
        r"FtpOpenFile(?:A|W)",
        r"Send(?:Ex)?(?:A|W)?\b",
        r"WSASend\b",
    ],
}


@dataclass
class DosHeader:
    """DOS Header (MZ)."""

    magic: int = 0x5A4D
    pe_offset: int = 0


@dataclass
class RichEntry:
    """Single Rich header entry."""

    build_id: int = 0
    product_id: int = 0
    tool_name: str = ""
    tool_build: int = 0
    count: int = 0


@dataclass
class FileHeader:
    """COFF File Header."""

    machine: int = 0
    machine_str: str = "Unknown"
    num_sections: int = 0
    timestamp: int = 0
    characteristics: int = 0


@dataclass
class OptionalHeader:
    """PE Optional Header (PE32/PE32+)."""

    magic: int = 0x10B
    is_64bit: bool = False
    linker_version: str = "0.0"
    size_of_code: int = 0
    size_of_initialized_data: int = 0
    size_of_uninitialized_data: int = 0
    entry_point: int = 0
    base_of_code: int = 0
    base_of_data: int = 0
    image_base: int = 0
    section_alignment: int = 0
    file_alignment: int = 0
    os_version: str = "0.0"
    subsystem: int = 0
    subsystem_str: str = "Unknown"
    dll_characteristics: int = 0
    size_of_image: int = 0
    size_of_headers: int = 0
    checksum: int = 0


@dataclass
class PESection:
    """PE Section header."""

    name: str = ""
    virtual_address: int = 0
    virtual_size: int = 0
    raw_size: int = 0
    raw_offset: int = 0
    characteristics: int = 0
    entropy: float = 0.0
    flags: list[str] = field(default_factory=list)


@dataclass
class ImportEntry:
    """Imported DLL with its functions."""

    dll: str = ""
    functions: list[str] = field(default_factory=list)


@dataclass
class ExportEntry:
    """Exported function."""

    ordinal: int = 0
    name: str = ""
    forwarded: str = ""


@dataclass
class ThreatIndicator:
    """Detected threat indicator."""

    category: str = ""
    description: str = ""
    severity: Severity = Severity.LOW
    evidence: str = ""


@dataclass
class PackerInfo:
    """Detected packing information."""

    name: str = ""
    confidence: float = 0.0
    indicators: list[str] = field(default_factory=list)


@dataclass
class OverlayInfo:
    """Overlay data appended after PE."""

    present: bool = False
    offset: int = 0
    size: int = 0
    md5: str = ""


@dataclass
class PEAnalysisResult:
    """Complete PE analysis result."""

    filename: str = ""
    filepath: str = ""
    file_size: int = 0
    md5: str = ""
    sha1: str = ""
    sha256: str = ""
    is_valid_pe: bool = False
    is_64bit: bool = False

    dos_header: DosHeader | None = None
    file_header: FileHeader | None = None
    optional_header: OptionalHeader | None = None
    rich_entries: list[RichEntry] = field(default_factory=list)
    sections: list[PESection] = field(default_factory=list)
    imports: list[ImportEntry] = field(default_factory=list)
    exports: list[ExportEntry] = field(default_factory=list)

    packer: PackerInfo | None = None
    overlay: OverlayInfo | None = None
    threat_indicators: list[ThreatIndicator] = field(default_factory=list)
    yara_matches: list[ThreatIndicator] = field(default_factory=list)
    vt_result: object | None = None
    suspicious_strings: list[str] = field(default_factory=list)
    all_strings: list[str] = field(default_factory=list)

    error: str | None = None

    @property
    def threat_score(self) -> int:
        if not self.threat_indicators:
            return 0
        score = 0
        weights = {
            Severity.CRITICAL: 40,
            Severity.HIGH: 25,
            Severity.MEDIUM: 10,
            Severity.LOW: 5,
        }
        for indicator in self.threat_indicators:
            score += weights.get(indicator.severity, 5)
        return min(score, 100)

    @property
    def risk_level(self) -> RiskLevel:
        score = self.threat_score
        if score >= 75:
            return RiskLevel.CRITICAL
        if score >= 50:
            return RiskLevel.HIGH
        if score >= 25:
            return RiskLevel.MEDIUM
        if score > 0:
            return RiskLevel.LOW
        return RiskLevel.CLEAN

    @property
    def entropy_score(self) -> float:
        if not self.sections:
            return 0.0
        total = sum(s.raw_size for s in self.sections if s.raw_size > 0)
        if total == 0:
            return 0.0
        weighted = sum(
            s.entropy * s.raw_size for s in self.sections if s.raw_size > 0
        )
        return round(weighted / total, 2)
