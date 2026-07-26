"""
Built-in YARA-style rules for malware pattern detection.

Uses pure-Python regex matching as a lightweight alternative to YARA,
providing pattern-based detection without external dependencies.

Copyright (c) 2026 s1d9e - MIT License
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class Rule:
    """A single detection rule."""

    name: str
    author: str = "s1d9e"
    description: str = ""
    severity: str = "MEDIUM"
    tags: list[str] = field(default_factory=list)
    strings: dict[str, str] = field(default_factory=dict)
    condition: str = "any"


@dataclass
class Match:
    """A rule match result."""

    rule_name: str
    severity: str
    description: str
    matched_patterns: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)


BUILTIN_RULES: list[Rule] = [
    Rule(
        name="Suspicious_PowerShell_Encoded",
        description="PowerShell with encoded/obfuscated command",
        severity="HIGH",
        tags=["powershell", "obfuscation", "execution"],
        strings={
            "ps_enc": r"powershell.*(?:-enc|-encodedcommand|-e)\s+[A-Za-z0-9+/=]{20,}",
            "ps_download": r"powershell.*(?:downloadstring|downloadfile|invoke-expression|IEX)",
        },
    ),
    Rule(
        name="Credential_Access_APIs",
        description="Credential theft API usage detected",
        severity="HIGH",
        tags=["credentials", "mimikatz", "lsa"],
        strings={
            "lsa": r"(?:LsaEnumerateLogonSessions|LsaGetLogonSessionData|SamQueryInformationUser)",
            "cred": r"(?:CredEnumerate|CredRead|CredWrite)",
            "dpapi": r"(?:CryptUnprotectData|CryptProtectData)",
            "sspi": r"(?:ImpersonateLoggedOnUser|RevertToSelf)",
        },
    ),
    Rule(
        name="Ransomware_Indicators",
        description="Potential ransomware behavior detected",
        severity="CRITICAL",
        tags=["ransomware", "encryption"],
        strings={
            "bitcoin": (
                r"(?:bitcoin|monero|ethereum|wallet|ransom|"
                r"decrypt|\.locked|\.encrypted|\.crypto)"
            ),
            "extensions": r"\.(?:locked|encrypted|crypto|crypt|enc)",
            "note": r"(?:how_to_decrypt|readme\.txt|restore_files)",
        },
    ),
    Rule(
        name="Persistence_Scheduled_Task",
        description="Scheduled task creation for persistence",
        severity="HIGH",
        tags=["persistence", "scheduled-task"],
        strings={
            "schtasks": r"schtasks\.exe\s+/(?:create|Change)",
            "at.exe": r"(?:at\.exe|net\s+schedule)",
            "xml_task": r"<Task\s+.*xmlns",
        },
    ),
    Rule(
        name="Network_C2_Communication",
        description="Command and control communication patterns",
        severity="HIGH",
        tags=["c2", "network", "backdoor"],
        strings={
            "beacon": r"(?:beacon|heartbeat|checkin|keepalive)",
            "http_post": r"HTTP/(?:1\.[01]|2)\s+.*POST",
            "dns": r"(?:nslookup|dnsquery|DnsQuery)",
            "tor": r"(?:\.onion|tor2web|torproxy)",
        },
    ),
    Rule(
        name="Process_Hollowing",
        description="Process hollowing / process injection technique",
        severity="CRITICAL",
        tags=["injection", "process-hollowing", "evasion"],
        strings={
            "hollow": r"(?:NtUnmapViewOfSection|ZwUnmapViewOfSection)",
            "write": r"(?:NtWriteVirtualMemory|WriteProcessMemory)",
            "thread": r"(?:CreateRemoteThread|NtCreateThreadEx|RtlCreateUserThread)",
            "alloc": r"(?:VirtualAllocEx|VirtualAlloc)",
        },
    ),
    Rule(
        name="Anti_Forensics",
        description="Anti-forensics techniques detected",
        severity="MEDIUM",
        tags=["anti-forensics", "evasion"],
        strings={
            "timestomp": r"(?:SetFileTime|SetFileAttributes|NtSetInformationFile)",
            "shredder": r"(?:shred|wipe|secure.?delete|sdelete)",
            "log_clear": r"(?:wevtutil\s+cl|Clear-EventLog|for\s+/l.*del)",
        },
    ),
    Rule(
        name="Cryptominer_Indicators",
        description="Cryptocurrency mining indicators",
        severity="MEDIUM",
        tags=["cryptominer", "mining"],
        strings={
            "pool": r"(?:stratum\+tcp|stratum\+ssl|nicehash|mining\.pool)",
            "algo": r"(?:cryptonight|randomx|ethash|argon2|scrypt)",
            "wallet": r"(?:4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}|bc1[a-zA-HJ-NP-Z0-9]{25,39})",
        },
    ),
    Rule(
        name="Living_off_the_Land",
        description="LOLBins usage for malicious purposes",
        severity="MEDIUM",
        tags=["lolbin", "evasion"],
        strings={
            "mshta": r"mshta\.exe\s+",
            "regsvr32": r"regsvr32\.exe\s+/(?:s|u|i:|scrobj)",
            "certutil": r"certutil\.exe\s+(?:-urlcache|-split|-f|-decode)",
            "bitsadmin": r"bitsadmin\.exe\s+/(?:transfer|create|addfile)",
            "wmic": r"wmic\.exe\s+(?:process|process\s+call\s+create)",
        },
    ),
    Rule(
        name="Data_Exfiltration",
        description="Data exfiltration techniques detected",
        severity="HIGH",
        tags=["exfiltration", "data-theft"],
        strings={
            "ftp": r"(?:ftp\.exe|WinInet|InternetOpen|FtpOpenFile)",
            "cloud": r"(?:onedrive|dropbox|google.?drive|mega\.nz|s3\.amazonaws)",
            "smtp": r"(?:smtp|mail\.send|CDO\.Message)",
            "compress": r"(?:7z\.exe|rar\.exe|tar\.gz|zip\.exe)",
        },
    ),
]


def scan_bytes(data: bytes, max_scan: int = 0x100000) -> list[Match]:
    """
    Scan byte data against built-in detection rules.

    Args:
        data: Raw bytes to scan
        max_scan: Maximum bytes to scan (default 1MB)

    Returns:
        List of rule matches
    """
    scan_data = data[:max_scan].decode("utf-8", errors="replace")
    matches: list[Match] = []

    for rule in BUILTIN_RULES:
        matched_patterns: list[str] = []

        for pattern_name, pattern in rule.strings.items():
            try:
                if re.search(pattern, scan_data, re.IGNORECASE | re.DOTALL):
                    matched_patterns.append(pattern_name)
            except re.error:
                continue

        if matched_patterns:
            matches.append(
                Match(
                    rule_name=rule.name,
                    severity=rule.severity,
                    description=rule.description,
                    matched_patterns=matched_patterns,
                    tags=rule.tags,
                )
            )

    return matches


def scan_strings(strings: list[str], max_scan: int = 5000) -> list[Match]:
    """
    Scan extracted strings against built-in detection rules.

    Args:
        strings: List of extracted strings
        max_scan: Maximum strings to scan

    Returns:
        List of rule matches
    """
    combined = "\n".join(strings[:max_scan])
    scan_data = combined.encode("utf-8", errors="ignore")
    return scan_bytes(scan_data)
