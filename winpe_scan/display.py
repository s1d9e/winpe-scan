"""
Terminal display engine -- rich colored output for PE analysis results.

Copyright (c) 2026 s1d9e - MIT License
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from winpe_scan.models import PEAnalysisResult, RiskLevel, Severity

try:
    from colorama import Fore, Style
    from colorama import init as colorama_init

    colorama_init(autoreset=True)

    class C:
        """Color shortcuts."""

        RED = Fore.RED
        BRIGHT_RED = Style.BRIGHT + Fore.RED
        GREEN = Fore.GREEN
        BRIGHT_GREEN = Style.BRIGHT + Fore.GREEN
        YELLOW = Fore.YELLOW
        BRIGHT_YELLOW = Style.BRIGHT + Fore.YELLOW
        BLUE = Fore.BLUE
        BRIGHT_BLUE = Style.BRIGHT + Fore.BLUE
        CYAN = Fore.CYAN
        BRIGHT_CYAN = Style.BRIGHT + Fore.CYAN
        MAGENTA = Fore.MAGENTA
        WHITE = Fore.WHITE
        DIM = Fore.LIGHTBLACK_EX
        BOLD = Style.BRIGHT
        RESET = Style.RESET_ALL

except ImportError:

    class C:  # type: ignore[no-redef]
        """No-op colors when colorama is missing."""

        RED = GREEN = YELLOW = BLUE = CYAN = MAGENTA = ""
        BRIGHT_RED = BRIGHT_GREEN = BRIGHT_YELLOW = ""
        BRIGHT_BLUE = BRIGHT_CYAN = ""
        WHITE = DIM = BOLD = RESET = ""


SEVERITY_COLORS: dict[Severity, str] = {
    Severity.CRITICAL: C.BRIGHT_RED,
    Severity.HIGH: C.RED,
    Severity.MEDIUM: C.YELLOW,
    Severity.LOW: C.DIM,
}

RISK_COLORS: dict[RiskLevel, str] = {
    RiskLevel.CRITICAL: C.BRIGHT_RED,
    RiskLevel.HIGH: C.RED,
    RiskLevel.MEDIUM: C.YELLOW,
    RiskLevel.LOW: C.DIM,
    RiskLevel.CLEAN: C.GREEN,
}

RISK_LABELS: dict[RiskLevel, str] = {
    RiskLevel.CRITICAL: "CRITICAL",
    RiskLevel.HIGH: "HIGH",
    RiskLevel.MEDIUM: "MEDIUM",
    RiskLevel.LOW: "LOW",
    RiskLevel.CLEAN: "CLEAN",
}

LINE = f"{C.DIM}{'─' * 68}{C.RESET}"
DOUBLE_LINE = f"{C.DIM}{'═' * 68}{C.RESET}"


def _entropy_bar(entropy: float, width: int = 20) -> str:
    """Render a visual entropy bar."""
    ratio = min(entropy / 8.0, 1.0)
    filled = int(ratio * width)
    empty = width - filled

    if entropy > 7.0:
        color = C.RED
    elif entropy > 5.5:
        color = C.YELLOW
    else:
        color = C.GREEN

    return f"{color}{'█' * filled}{'░' * empty}{C.RESET} {entropy:.2f}"


def _risk_bar(score: int, width: int = 30) -> str:
    """Render a threat score bar."""
    filled = int((score / 100) * width)
    empty = width - filled

    if score >= 75:
        color = C.RED
    elif score >= 50:
        color = C.YELLOW
    elif score > 0:
        color = C.CYAN
    else:
        color = C.GREEN

    return f"{color}{'█' * filled}{'░' * empty}{C.RESET}"


def _severity_badge(severity: Severity) -> str:
    color = SEVERITY_COLORS.get(severity, C.DIM)
    return f"{color}[{severity.value:>8}]{C.RESET}"


def print_banner() -> None:
    """Print the tool banner."""
    cmds = (
        "info | scan | strings | hash |"
        " headers | sections | imports | compare | sig"
    )
    print(
        f"\n{C.RED}{'═' * 72}{C.RESET}\n"
        f"{C.RED}║{C.RESET}"
        f"  {C.BRIGHT_CYAN}W I N P E - S C A N{C.RESET}"
        f"  {C.DIM}v2.0{C.RESET}\n"
        f"{C.RED}║{C.RESET}"
        f"  {C.DIM}Windows PE Multi-Tool Analyzer{C.RESET}\n"
        f"{C.RED}║{C.RESET}"
        f"  {C.DIM}For authorized security research only{C.RESET}\n"
        f"{C.RED}{'═' * 72}{C.RESET}\n"
        f"  {C.WHITE}Commands:{C.RESET}  {cmds}\n"
        f"  {C.WHITE}Usage:{C.RESET}     winpe-scan <command> [options]\n"
        f"  {C.WHITE}Help:{C.RESET}      winpe-scan <command> --help\n"
    )


def print_info(result: PEAnalysisResult) -> None:
    """Print full analysis report."""
    risk_color = RISK_COLORS.get(result.risk_level, C.DIM)

    # -- Header --
    print(
        f"\n{C.BRIGHT_CYAN}{'═' * 72}{C.RESET}\n"
        f"{C.BOLD}  PE ANALYSIS REPORT{C.RESET}  {C.DIM}-- {result.filename}{C.RESET}\n"
        f"{C.BRIGHT_CYAN}{'═' * 72}{C.RESET}\n"
    )

    # -- Threat Score --
    score = result.threat_score
    risk_label = RISK_LABELS[result.risk_level]
    score_line = (
        f"  {C.BOLD}Threat Score:{C.RESET}  {_risk_bar(score)}"
        f"  {risk_color}{C.BOLD}{score}/100 [{risk_label}]{C.RESET}"
    )
    print(score_line)
    print(f"  {C.DIM}{'─' * 72}{C.RESET}\n")

    if result.error:
        print(f"  {C.RED}ERROR: {result.error}{C.RESET}\n")
        return

    # -- File Info --
    print(f"  {C.BRIGHT_CYAN}[ FILE INFO ]{C.RESET}")
    print(f"  {C.DIM}{LINE}{C.RESET}")
    print(f"  {C.WHITE}{'File:':<16}{C.RESET} {C.CYAN}{result.filename}{C.RESET}")
    size_str = f"{result.file_size:,} bytes {_human_size(result.file_size)}"
    print(f"  {C.WHITE}{'Size:':<16}{C.RESET} {C.CYAN}{size_str}{C.RESET}")
    print(f"  {C.WHITE}{'MD5:':<16}{C.RESET} {C.YELLOW}{result.md5}{C.RESET}")
    print(f"  {C.WHITE}{'SHA1:':<16}{C.RESET} {C.YELLOW}{result.sha1}{C.RESET}")
    print(f"  {C.WHITE}{'SHA256:':<16}{C.RESET} {C.YELLOW}{result.sha256}{C.RESET}")
    print()

    # -- DOS Header --
    if result.dos_header:
        dh = result.dos_header
        print(f"  {C.BRIGHT_CYAN}[ DOS HEADER ]{C.RESET}")
        print(f"  {C.DIM}{LINE}{C.RESET}")
        print(f"  {C.WHITE}{'Magic:':<16}{C.RESET} {C.GREEN}0x{dh.magic:04X} (MZ){C.RESET}")
        pe_off = f"0x{dh.pe_offset:08X}"
        print(f"  {C.WHITE}{'PE Offset:':<16}{C.RESET} {C.CYAN}{pe_off}{C.RESET}")
        print()

    # -- Rich Header --
    if result.rich_entries:
        count = len(result.rich_entries)
        print(f"  {C.BRIGHT_CYAN}[ RICH HEADER ]{C.RESET}  {C.DIM}({count} entries){C.RESET}")
        print(f"  {C.DIM}{LINE}{C.RESET}")
        print(f"  {C.WHITE}{'Tool':<35} {'Build':<8} {'Count':<8}{C.RESET}")
        print(f"  {C.DIM}{'─' * 55}{C.RESET}")
        for entry in result.rich_entries[:20]:
            tool_display = f"{entry.tool_name} ({entry.product_id:#06x})"
            build = entry.build_id
            cnt = entry.count
            print(
                f"  {C.CYAN}{tool_display:<35}"
                f" {C.GREEN}{build:<8}"
                f" {C.YELLOW}{cnt:<8}{C.RESET}"
            )
        if len(result.rich_entries) > 20:
            remaining = len(result.rich_entries) - 20
            print(f"  {C.DIM}... and {remaining} more entries{C.RESET}")
        print()

    # -- File Header --
    if result.file_header:
        fh = result.file_header
        ts_str = "Unknown"
        if fh.timestamp > 0:
            try:
                ts_str = datetime.utcfromtimestamp(
                    fh.timestamp
                ).strftime("%Y-%m-%d %H:%M:%S UTC")
            except (OSError, ValueError):
                ts_str = f"0x{fh.timestamp:08X}"

        print(f"  {C.BRIGHT_CYAN}[ FILE HEADER ]{C.RESET}")
        print(f"  {C.DIM}{LINE}{C.RESET}")
        print(f"  {C.WHITE}{'Machine:':<16}{C.RESET} {C.GREEN}{fh.machine_str}{C.RESET}")
        print(f"  {C.WHITE}{'Sections:':<16}{C.RESET} {C.GREEN}{fh.num_sections}{C.RESET}")
        print(f"  {C.WHITE}{'Timestamp:':<16}{C.RESET} {C.CYAN}{ts_str}{C.RESET}")
        chars_hex = f"0x{fh.characteristics:04X}"
        print(f"  {C.WHITE}{'Characteristics:':<16}{C.RESET} {C.DIM}{chars_hex}{C.RESET}")
        print()

    # -- Optional Header --
    if result.optional_header:
        oh = result.optional_header
        arch = "PE32+ (64-bit)" if oh.is_64bit else "PE32 (32-bit)"
        print(f"  {C.BRIGHT_CYAN}[ OPTIONAL HEADER ]{C.RESET}  {C.DIM}{arch}{C.RESET}")
        print(f"  {C.DIM}{LINE}{C.RESET}")
        print(f"  {C.WHITE}{'Linker:':<16}{C.RESET} {C.GREEN}{oh.linker_version}{C.RESET}")
        ep = f"0x{oh.entry_point:08X}"
        print(f"  {C.WHITE}{'Entry Point:':<16}{C.RESET} {C.CYAN}{ep}{C.RESET}")
        ib = f"0x{oh.image_base:016X}"
        print(f"  {C.WHITE}{'Image Base:':<16}{C.RESET} {C.CYAN}{ib}{C.RESET}")
        print(f"  {C.WHITE}{'Subsystem:':<16}{C.RESET} {C.GREEN}{oh.subsystem_str}{C.RESET}")
        img = f"0x{oh.size_of_image:08X}"
        print(f"  {C.WHITE}{'Size of Image:':<16}{C.RESET} {C.CYAN}{img}{C.RESET}")
        cs = f"0x{oh.checksum:08X}"
        print(f"  {C.WHITE}{'Checksum:':<16}{C.RESET} {C.DIM}{cs}{C.RESET}")

        # DLL characteristics flags
        chars: list[str] = []
        if oh.dll_characteristics & 0x0020:
            chars.append("HIGH_ENTROPY_VA")
        if oh.dll_characteristics & 0x0040:
            chars.append("DYNAMIC_BASE")
        if oh.dll_characteristics & 0x0080:
            chars.append("FORCE_INTEGRITY")
        if oh.dll_characteristics & 0x0100:
            chars.append("NX_COMPAT")
        if oh.dll_characteristics & 0x0400:
            chars.append("NO_SEH")
        if oh.dll_characteristics & 0x4000:
            chars.append("GUARD_CF")
        if oh.dll_characteristics & 0x8000:
            chars.append("TERMINAL_SERVER_AWARE")
        if chars:
            flags_str = ", ".join(chars)
            print(f"  {C.WHITE}{'DLL Flags:':<16}{C.RESET} {C.DIM}{flags_str}{C.RESET}")
        print()

    # -- Sections --
    if result.sections:
        sec_count = len(result.sections)
        print(f"  {C.BRIGHT_CYAN}[ SECTIONS ]{C.RESET}  {C.DIM}({sec_count} sections){C.RESET}")
        print(f"  {C.DIM}{LINE}{C.RESET}")
        hdr = (
            f"  {C.WHITE}{'Name':<10} {'VirtAddr':<12}"
            f" {'VirtSize':<12} {'RawSize':<12}"
            f" {'Entropy':<25} Flags{C.RESET}"
        )
        print(hdr)
        print(f"  {C.DIM}{'─' * 85}{C.RESET}")

        for sec in result.sections:
            ent = _entropy_bar(sec.entropy)
            flag_str = " ".join(sec.flags[:4]) if sec.flags else "-"
            print(
                f"  {C.WHITE}{sec.name:<10} "
                f"{C.CYAN}0x{sec.virtual_address:08X}   "
                f"{C.CYAN}0x{sec.virtual_size:08X}   "
                f"{C.CYAN}0x{sec.raw_size:08X}   "
                f"{ent}  "
                f"{C.DIM}{flag_str}{C.RESET}"
            )
        print()

    # -- Imports --
    if result.imports:
        dll_count = len(result.imports)
        print(f"  {C.BRIGHT_CYAN}[ IMPORTS ]{C.RESET}  {C.DIM}({dll_count} DLLs){C.RESET}")
        print(f"  {C.DIM}{LINE}{C.RESET}")

        for imp in result.imports[:20]:
            funcs_display = ", ".join(imp.functions[:6])
            suffix = ""
            if len(imp.functions) > 6:
                extra = len(imp.functions) - 6
                suffix = f" {C.DIM}...+{extra}{C.RESET}"
            print(
                f"  {C.GREEN}{imp.dll:<25}{C.RESET}"
                f" {C.DIM}->{C.RESET} {C.CYAN}{funcs_display}{C.RESET}{suffix}"
            )

        if len(result.imports) > 20:
            extra = len(result.imports) - 20
            print(f"  {C.DIM}... and {extra} more DLLs{C.RESET}")
        print()

    # -- Exports --
    if result.exports:
        exp_count = len(result.exports)
        print(f"  {C.BRIGHT_CYAN}[ EXPORTS ]{C.RESET}  {C.DIM}({exp_count} functions){C.RESET}")
        print(f"  {C.DIM}{LINE}{C.RESET}")

        for exp in result.exports[:20]:
            print(f"  {C.YELLOW}{exp.ordinal:>5}{C.RESET}  {C.CYAN}{exp.name}{C.RESET}")

        if len(result.exports) > 20:
            extra = len(result.exports) - 20
            print(f"  {C.DIM}... and {extra} more exports{C.RESET}")
        print()

    # -- Packer Detection --
    if result.packer:
        conf_color = C.RED if result.packer.confidence > 0.7 else C.YELLOW
        pct = result.packer.confidence * 100
        print(f"  {C.BRIGHT_RED}[ PACKER DETECTED ]{C.RESET}")
        print(f"  {C.DIM}{LINE}{C.RESET}")
        print(f"  {C.WHITE}{'Packer:':<16}{C.RESET} {C.RED}{C.BOLD}{result.packer.name}{C.RESET}")
        print(f"  {C.WHITE}{'Confidence:':<16}{C.RESET} {conf_color}{pct:.0f}%{C.RESET}")
        for packer_note in result.packer.indicators:
            print(f"  {C.DIM}  * {packer_note}{C.RESET}")
        print()

    # -- Overlay --
    if result.overlay and result.overlay.present:
        print(f"  {C.BRIGHT_CYAN}[ OVERLAY ]{C.RESET}")
        print(f"  {C.DIM}{LINE}{C.RESET}")
        off_str = f"0x{result.overlay.offset:08X}"
        print(f"  {C.WHITE}{'Offset:':<16}{C.RESET} {C.CYAN}{off_str}{C.RESET}")
        size_human = f"{result.overlay.size:,} bytes {_human_size(result.overlay.size)}"
        print(f"  {C.WHITE}{'Size:':<16}{C.RESET} {C.CYAN}{size_human}{C.RESET}")
        print(f"  {C.WHITE}{'MD5:':<16}{C.RESET} {C.YELLOW}{result.overlay.md5}{C.RESET}")
        print()

    # -- Threat Indicators --
    if result.threat_indicators:
        ti_count = len(result.threat_indicators)
        print(
            f"  {C.BRIGHT_RED}[ THREAT INDICATORS ]{C.RESET}"
            f"  {C.DIM}({ti_count} found){C.RESET}"
        )
        print(f"  {C.DIM}{LINE}{C.RESET}")

        sorted_indicators = sorted(
            result.threat_indicators,
            key=lambda x: list(Severity).index(x.severity),
            reverse=True,
        )

        for threat in sorted_indicators:
            badge = _severity_badge(threat.severity)
            is_critical = threat.severity in (Severity.CRITICAL, Severity.HIGH)
            cat_color = C.MAGENTA if is_critical else C.CYAN
            print(
                f"  {badge} {cat_color}[{threat.category}]{C.RESET}"
                f" {threat.description}"
            )
            if threat.evidence:
                evidence_short = threat.evidence[:100]
                print(f"           {C.DIM}{evidence_short}{C.RESET}")
        print()

    # -- Strings Summary --
    if result.suspicious_strings:
        ss_count = len(result.suspicious_strings)
        print(
            f"  {C.BRIGHT_YELLOW}[ SUSPICIOUS STRINGS ]{C.RESET}"
            f"  {C.DIM}({ss_count} matched){C.RESET}"
        )
        print(f"  {C.DIM}{LINE}{C.RESET}")
        for sus_str in result.suspicious_strings[:10]:
            display = sus_str[:80] + "..." if len(sus_str) > 80 else sus_str
            print(f"  {C.YELLOW}->{C.RESET} {display}")
        if len(result.suspicious_strings) > 10:
            extra = len(result.suspicious_strings) - 10
            print(f"  {C.DIM}... and {extra} more{C.RESET}")
        print()

    # -- YARA Rules --
    if result.yara_matches:
        ym_count = len(result.yara_matches)
        print(
            f"  {C.BRIGHT_RED}[ YARA RULES ]{C.RESET}"
            f"  {C.DIM}({ym_count} rules matched){C.RESET}"
        )
        print(f"  {C.DIM}{LINE}{C.RESET}")
        for ym in result.yara_matches:
            badge = _severity_badge(ym.severity)
            print(f"  {badge} {C.MAGENTA}{ym.description}{C.RESET}")
            if ym.evidence:
                print(f"           {C.DIM}{ym.evidence}{C.RESET}")
        print()

    # -- VirusTotal --
    vt = getattr(result, "vt_result", None)
    if vt is not None:
        print(f"  {C.BRIGHT_CYAN}[ VIRUSTOTAL ]{C.RESET}")
        print(f"  {C.DIM}{LINE}{C.RESET}")
        if vt.error:
            print(f"  {C.YELLOW}[!] {vt.error}{C.RESET}")
        elif vt.found:
            det_color = C.RED if vt.malicious else C.GREEN
            print(
                f"  {C.WHITE}{'Status:':<16}{C.RESET}"
                f" {C.GREEN}Found{C.RESET}"
            )
            print(
                f"  {C.WHITE}{'Detections:':<16}{C.RESET}"
                f" {det_color}{C.BOLD}{vt.detection_ratio}{C.RESET}"
            )
            if vt.names:
                print(
                    f"  {C.WHITE}{'Known as:':<16}{C.RESET}"
                    f" {C.CYAN}{vt.names[0]}{C.RESET}"
                )
            if vt.tags:
                print(
                    f"  {C.WHITE}{'Tags:':<16}{C.RESET}"
                    f" {C.DIM}{', '.join(vt.tags[:8])}{C.RESET}"
                )
        else:
            print(
                f"  {C.DIM}Not found in VirusTotal database{C.RESET}"
            )
        print()

    # -- Footer --
    print(f"  {C.DIM}{DOUBLE_LINE}{C.RESET}")
    ti_count = len(result.threat_indicators)
    print(
        f"  {C.DIM}Analysis complete.{C.RESET}"
        f"  Threat indicators: {risk_color}{ti_count}{C.RESET}"
        f"  |  Risk: {risk_color}{C.BOLD}{risk_label}{C.RESET}"
        f"  |  Entropy: {C.CYAN}{result.entropy_score:.2f}{C.RESET}"
    )
    print(f"  {C.DIM}{DOUBLE_LINE}{C.RESET}\n")


def print_json(result: PEAnalysisResult) -> None:
    """Print result as JSON to stdout."""
    data: dict[str, Any] = {
        "filename": result.filename,
        "file_size": result.file_size,
        "md5": result.md5,
        "sha1": result.sha1,
        "sha256": result.sha256,
        "is_valid_pe": result.is_valid_pe,
        "is_64bit": result.is_64bit,
        "threat_score": result.threat_score,
        "risk_level": result.risk_level.value,
        "entropy_score": result.entropy_score,
        "error": result.error,
    }

    if result.file_header:
        data["machine"] = result.file_header.machine_str
        data["num_sections"] = result.file_header.num_sections
        data["timestamp"] = result.file_header.timestamp

    if result.optional_header:
        oh = result.optional_header
        data["entry_point"] = f"0x{oh.entry_point:08X}"
        data["image_base"] = f"0x{oh.image_base:X}"
        data["subsystem"] = oh.subsystem_str
        data["linker_version"] = oh.linker_version

    if result.sections:
        data["sections"] = [
            {
                "name": s.name,
                "virtual_address": f"0x{s.virtual_address:08X}",
                "virtual_size": s.virtual_size,
                "raw_size": s.raw_size,
                "entropy": s.entropy,
                "flags": s.flags,
            }
            for s in result.sections
        ]

    if result.imports:
        data["imports"] = [
            {"dll": imp.dll, "functions": imp.functions}
            for imp in result.imports
        ]

    if result.exports:
        data["exports"] = [
            {"ordinal": e.ordinal, "name": e.name}
            for e in result.exports
        ]

    if result.packer:
        data["packer"] = {
            "name": result.packer.name,
            "confidence": result.packer.confidence,
            "indicators": result.packer.indicators,
        }

    if result.overlay and result.overlay.present:
        data["overlay"] = {
            "offset": result.overlay.offset,
            "size": result.overlay.size,
            "md5": result.overlay.md5,
        }

    if result.rich_entries:
        data["rich_header"] = [
            {
                "tool_name": e.tool_name,
                "build_id": e.build_id,
                "product_id": e.product_id,
                "count": e.count,
            }
            for e in result.rich_entries
        ]

    if result.threat_indicators:
        data["threat_indicators"] = [
            {
                "severity": ti.severity.value,
                "category": ti.category,
                "description": ti.description,
                "evidence": ti.evidence,
            }
            for ti in result.threat_indicators
        ]

    if result.suspicious_strings:
        data["suspicious_strings"] = result.suspicious_strings

    if result.yara_matches:
        data["yara_matches"] = [
            {
                "rule": ym.description,
                "severity": ym.severity.value,
                "patterns": ym.evidence,
            }
            for ym in result.yara_matches
        ]

    vt = getattr(result, "vt_result", None)
    if vt is not None and not vt.error:
        data["virustotal"] = {
            "found": vt.found,
            "detection_ratio": vt.detection_ratio,
            "malicious": vt.malicious,
            "tags": vt.tags,
            "names": vt.names,
        }

    print(json.dumps(data, indent=2, ensure_ascii=False))


def _human_size(size: int) -> str:
    """Format byte count as human-readable string."""
    for unit in ("B", "KB", "MB", "GB"):
        if abs(size) < 1024:
            return f" ({size:.1f} {unit})"
        size /= 1024  # type: ignore[assignment]
    return f" ({size:.1f} TB)"
