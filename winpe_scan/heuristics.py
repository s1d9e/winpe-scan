"""
Heuristic analysis engine — threat detection via pattern matching,
behavioral signatures, structural anomalies, and entropy analysis.

Copyright (c) 2026 s1d9e — MIT License
"""

from __future__ import annotations

import re

from winpe_scan.models import (
    ANTI_DEBUG_APIS,
    ANTI_VM_APIS,
    PACKER_SIGNATURES,
    PERSISTENCE_APIS,
    PRIVILEGE_ESCALATION_APIS,
    PROCESS_INJECTION_APIS,
    SUSPICIOUS_DLLS,
    SUSPICIOUS_PATTERNS,
    PackerInfo,
    PEAnalysisResult,
    Severity,
    ThreatIndicator,
)


def analyze(result: PEAnalysisResult) -> PEAnalysisResult:
    """Run all heuristic checks on a parsed PE result."""
    if not result.is_valid_pe:
        return result

    _detect_packer(result)
    _detect_section_anomalies(result)
    _detect_import_anomalies(result)
    _detect_suspicious_apis(result)
    _detect_suspicious_strings(result)
    _detect_structural_anomalies(result)
    _detect_overlay_threats(result)
    _scan_yara_rules(result)

    return result


def _detect_packer(result: PEAnalysisResult) -> None:
    """Identify known packers/crypters by section names and patterns."""
    section_names = {s.name for s in result.sections}
    high_entropy_sections = [
        s for s in result.sections if s.entropy > 7.5
    ]

    for packer_name, signatures in PACKER_SIGNATURES.items():
        indicators: list[str] = []
        confidence = 0.0

        raw_sections = signatures.get("section_names")
        packer_sections: set[str] = (
            set(raw_sections) if raw_sections else set()  # type: ignore[call-overload]
        )
        overlap = section_names & packer_sections
        if overlap:
            indicators.append(
                f"Known section(s): {', '.join(overlap)}"
            )
            confidence = max(confidence, 0.85)

        ep_bytes = signatures.get("ep_bytes")
        if ep_bytes and result.optional_header:
            ep = result.optional_header.entry_point
            data: bytes = bytes(ep_bytes)  # type: ignore[call-overload]
            if ep > 0 and ep + len(data) <= result.file_size:
                indicators.append(
                    f"Entry point bytes match {packer_name} signature"
                )
                confidence = max(confidence, 0.95)

        if len(high_entropy_sections) >= 2:
            count = len(high_entropy_sections)
            indicators.append(
                f"{count} sections with very high entropy (>7.5)"
            )
            confidence = max(confidence, 0.6)

        if confidence > 0:
            result.packer = PackerInfo(
                name=packer_name,
                confidence=min(confidence, 1.0),
                indicators=indicators,
            )
            result.threat_indicators.append(
                ThreatIndicator(
                    category="PACKER",
                    description=(
                        f"Detected packer/crypter: {packer_name}"
                    ),
                    severity=(
                        Severity.HIGH if confidence > 0.7
                        else Severity.MEDIUM
                    ),
                    evidence="; ".join(indicators),
                )
            )
            break  # One packer match is sufficient


def _detect_section_anomalies(result: PEAnalysisResult) -> None:
    """Flag suspicious section characteristics."""
    for sec in result.sections:
        flags = set(sec.flags)

        # Writable and executable section — classic malware trait
        if "WRITE" in flags and "EXEC" in flags:
            chars = "|".join(flags)
            result.threat_indicators.append(
                ThreatIndicator(
                    category="SECTION",
                    description=(
                        f"Section '{sec.name}' is writable + executable"
                        f" (W^X violation)"
                    ),
                    severity=Severity.HIGH,
                    evidence=f"Characteristics: {chars}",
                )
            )

        # Section with name longer than 8 chars (unusual)
        if len(sec.name) > 8:
            result.threat_indicators.append(
                ThreatIndicator(
                    category="SECTION",
                    description=(
                        f"Section name '{sec.name}' exceeds "
                        f"8 characters"
                    ),
                    severity=Severity.LOW,
                    evidence=f"Name length: {len(sec.name)}",
                )
            )

        # Entropy anomaly: very high in code section
        if sec.entropy > 7.8 and "CODE" in flags:
            result.threat_indicators.append(
                ThreatIndicator(
                    category="SECTION",
                    description=(
                        f"Code section '{sec.name}' has extremely "
                        f"high entropy ({sec.entropy:.2f})"
                    ),
                    severity=Severity.MEDIUM,
                    evidence="May indicate encrypted/packed code",
                )
            )

        if sec.entropy > 7.0 and "EXEC" in flags:
            result.threat_indicators.append(
                ThreatIndicator(
                    category="SECTION",
                    description=(
                        f"Executable section '{sec.name}' entropy "
                        f"{sec.entropy:.2f}"
                    ),
                    severity=Severity.LOW,
                    evidence=(
                        "Elevated entropy in executable section"
                    ),
                )
            )

        # Zero raw size but non-zero virtual size
        if sec.raw_size == 0 and sec.virtual_size > 0:
            vsize = f"0x{sec.virtual_size:X}"
            result.threat_indicators.append(
                ThreatIndicator(
                    category="SECTION",
                    description=(
                        f"Section '{sec.name}' has virtual size "
                        f"but no raw data"
                    ),
                    severity=Severity.LOW,
                    evidence=f"VirtualSize={vsize}, RawSize=0x0",
                )
            )


def _detect_import_anomalies(result: PEAnalysisResult) -> None:
    """Flag anomalous import table characteristics."""
    total_dlls = len(result.imports)
    total_functions = sum(
        len(imp.functions) for imp in result.imports
    )

    # Very few imports — possible dynamic resolution / unpacking stub
    if total_dlls == 0:
        result.threat_indicators.append(
            ThreatIndicator(
                category="IMPORT",
                description="No imports detected",
                severity=Severity.MEDIUM,
                evidence=(
                    "Empty import table — may use dynamic "
                    "API resolution"
                ),
            )
        )
    elif total_dlls <= 2 and total_functions <= 5:
        result.threat_indicators.append(
            ThreatIndicator(
                category="IMPORT",
                description=(
                    f"Minimal imports: {total_dlls} DLL(s), "
                    f"{total_functions} function(s)"
                ),
                severity=Severity.MEDIUM,
                evidence=(
                    "Suspiciously few imports — possible "
                    "runtime resolution"
                ),
            )
        )

    # Check for known suspicious DLLs used together
    import_dlls = {imp.dll.lower() for imp in result.imports}
    suspicious_combos = []
    for dll, reason in SUSPICIOUS_DLLS.items():
        if dll in import_dlls:
            suspicious_combos.append(f"{dll} ({reason})")

    if len(suspicious_combos) >= 3:
        count = len(suspicious_combos)
        result.threat_indicators.append(
            ThreatIndicator(
                category="IMPORT",
                description=(
                    f"Multiple suspicious DLLs imported ({count})"
                ),
                severity=Severity.MEDIUM,
                evidence="; ".join(suspicious_combos[:8]),
            )
        )

    # Imports from unusual DLLs
    known_safe = {
        "kernel32.dll", "ntdll.dll", "user32.dll", "gdi32.dll",
        "msvcrt.dll", "advapi32.dll", "ole32.dll",
        "oleaut32.dll", "shell32.dll", "comctl32.dll",
        "comdlg32.dll", "shlwapi.dll", "version.dll",
    }
    unusual = import_dlls - known_safe - set(
        SUSPICIOUS_DLLS.keys()
    )
    if unusual and len(result.sections) > 0:
        suspicious_import_names = [
            imp.dll for imp in result.imports
            if imp.dll in unusual
        ]
        if suspicious_import_names:
            result.threat_indicators.append(
                ThreatIndicator(
                    category="IMPORT",
                    description=(
                        f"Uncommon DLLs imported ({len(unusual)})"
                    ),
                    severity=Severity.LOW,
                    evidence="; ".join(sorted(unusual)[:10]),
                )
            )


def _detect_suspicious_apis(result: PEAnalysisResult) -> None:
    """Detect API functions associated with malicious behavior."""
    all_imported: set[str] = set()
    for imp in result.imports:
        for func in imp.functions:
            all_imported.add(func)

    category_checks = [
        ("ANTI-DEBUG", ANTI_DEBUG_APIS, Severity.HIGH),
        ("ANTI-VM", ANTI_VM_APIS, Severity.HIGH),
        ("INJECTION", PROCESS_INJECTION_APIS, Severity.CRITICAL),
        ("PRIVESC", PRIVILEGE_ESCALATION_APIS, Severity.HIGH),
        ("PERSISTENCE", PERSISTENCE_APIS, Severity.MEDIUM),
    ]

    for category, api_dict, base_severity in category_checks:
        found = []
        for api_name, description in api_dict.items():
            if api_name in all_imported:
                found.append(f"{api_name}: {description}")

        if found:
            severity = base_severity
            # Escalate if multiple APIs from the same category
            if len(found) >= 3:
                severity = Severity.CRITICAL
            elif len(found) >= 2:
                severity = Severity.HIGH

            result.threat_indicators.append(
                ThreatIndicator(
                    category=category,
                    description=(
                        f"{len(found)} {category.lower()} "
                        f"API(s) detected"
                    ),
                    severity=severity,
                    evidence="; ".join(found[:10]),
                )
            )


def _detect_suspicious_strings(
    result: PEAnalysisResult,
) -> None:
    """Match strings against known malicious patterns."""
    flagged: list[dict[str, str]] = []

    for category, patterns in SUSPICIOUS_PATTERNS.items():
        for pattern in patterns:
            try:
                regex = re.compile(pattern, re.IGNORECASE)
            except re.error:
                continue

            for s in result.all_strings[:2000]:
                match = regex.search(s)
                if match:
                    evidence = match.group(0)[:120]
                    flagged.append(
                        {
                            "category": category,
                            "evidence": evidence,
                            "pattern": pattern,
                        }
                    )
                    break  # One match per pattern

    # Deduplicate by category + evidence
    seen: set[tuple[str, str]] = set()
    unique: list[dict[str, str]] = []
    for item in flagged:
        key = (item["category"], item["evidence"][:60])
        if key not in seen:
            seen.add(key)
            unique.append(item)
    flagged = unique

    severity_map = {
        "COMMAND": Severity.HIGH,
        "CRYPTO": Severity.MEDIUM,
        "NETWORK": Severity.MEDIUM,
        "OBFUSCATION": Severity.HIGH,
        "DATA_EXFILTRATION": Severity.HIGH,
    }

    for item in flagged:
        cat = item["category"]
        result.threat_indicators.append(
            ThreatIndicator(
                category=cat,
                description=f"Suspicious {cat.lower()} pattern detected",
                severity=severity_map.get(cat, Severity.MEDIUM),
                evidence=item["evidence"],
            )
        )

    result.suspicious_strings = [
        item["evidence"] for item in flagged[:50]
    ]


def _detect_structural_anomalies(
    result: PEAnalysisResult,
) -> None:
    """Detect structural anomalies in PE headers."""
    if not result.optional_header or not result.file_header:
        return

    oh = result.optional_header

    # Checksum mismatch
    if oh.checksum != 0:
        computed = _compute_pe_checksum(result)
        if computed != oh.checksum:
            result.threat_indicators.append(
                ThreatIndicator(
                    category="INTEGRITY",
                    description="PE checksum mismatch",
                    severity=Severity.LOW,
                    evidence=(
                        f"Header: 0x{oh.checksum:08X}, "
                        f"Computed: 0x{computed:08X}"
                    ),
                )
            )

    # Missing security mitigations (DllCharacteristics)
    aslr_flag = 0x0040
    dep_flag = 0x0100
    cfg_flag = 0x4000
    safeguard_flag = 0x0200

    dll_chars = oh.dll_characteristics
    missing_mitigations = []
    if not (dll_chars & aslr_flag):
        missing_mitigations.append("ASLR")
    if not (dll_chars & dep_flag):
        missing_mitigations.append("DEP/NX")
    if not (dll_chars & cfg_flag):
        missing_mitigations.append("CFG")
    if not (dll_chars & safeguard_flag):
        missing_mitigations.append("GS Stack Cookie")

    if missing_mitigations:
        count = len(missing_mitigations)
        severity = (
            Severity.MEDIUM if count >= 3 else Severity.LOW
        )
        result.threat_indicators.append(
            ThreatIndicator(
                category="HARDENING",
                description=(
                    f"Missing security mitigations ({count})"
                ),
                severity=severity,
                evidence=(
                    "Missing: " + ", ".join(missing_mitigations)
                ),
            )
        )

    # Entry point outside code section
    if result.sections:
        first_code = None
        for sec in result.sections:
            if (
                "CODE" in sec.flags
                or sec.name.lower() in (".text", "code")
            ):
                first_code = sec
                break

        if first_code and oh.entry_point > 0:
            ep_va = oh.entry_point
            code_start = first_code.virtual_address
            code_end = code_start + first_code.virtual_size
            if ep_va < code_start or ep_va >= code_end:
                result.threat_indicators.append(
                    ThreatIndicator(
                        category="STRUCTURE",
                        description=(
                            "Entry point outside primary "
                            "code section"
                        ),
                        severity=Severity.HIGH,
                        evidence=(
                            f"EP=0x{ep_va:08X}, Code section "
                            f"starts at 0x{code_start:08X}"
                        ),
                    )
                )


def _detect_overlay_threats(result: PEAnalysisResult) -> None:
    """Flag suspicious overlay data."""
    if not result.overlay or not result.overlay.present:
        return

    overlay_size = result.overlay.size
    pe_size = result.file_size - overlay_size

    if overlay_size > pe_size:
        result.threat_indicators.append(
            ThreatIndicator(
                category="OVERLAY",
                description="Overlay larger than PE image",
                severity=Severity.HIGH,
                evidence=(
                    f"Overlay: {overlay_size:,} bytes, "
                    f"PE: {pe_size:,} bytes"
                ),
            )
        )
    elif overlay_size > 1024 * 100:  # > 100KB
        result.threat_indicators.append(
            ThreatIndicator(
                category="OVERLAY",
                description=(
                    "Significant overlay data detected"
                ),
                severity=Severity.MEDIUM,
                evidence=(
                    f"Overlay size: {overlay_size:,} bytes "
                    f"at offset 0x{overlay_size:X}"
                ),
            )
        )


def _compute_pe_checksum(result: PEAnalysisResult) -> int:
    """Compute the PE checksum (placeholder)."""
    return 0


def _scan_yara_rules(result: PEAnalysisResult) -> None:
    """Scan strings against built-in YARA-style rules."""
    from winpe_scan.yara_rules import scan_strings

    matches = scan_strings(result.all_strings)
    severity_map = {
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
    }

    for match in matches:
        sev = severity_map.get(match.severity, Severity.MEDIUM)
        result.yara_matches.append(
            ThreatIndicator(
                category="YARA",
                description=f"Rule '{match.rule_name}': {match.description}",
                severity=sev,
                evidence=", ".join(match.matched_patterns),
            )
        )

    # Add YARA matches to threat score
    result.threat_indicators.extend(result.yara_matches)
