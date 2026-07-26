"""
CLI entry point — argument parsing and command dispatch.

Copyright (c) 2026 s1d9e — MIT License
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from winpe_scan import __version__
from winpe_scan.display import (
    C,
    print_banner,
    print_info,
    print_json,
)
from winpe_scan.heuristics import analyze
from winpe_scan.models import PEAnalysisResult
from winpe_scan.pe_parser import PEParser


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="winpe-scan",
        description="Windows PE Multi-Tool Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  winpe-scan info malware.exe\n"
            "  winpe-scan info malware.exe --json\n"
            "  winpe-scan strings malware.exe --filter http\n"
            "  winpe-scan hash malware.exe\n"
            "  winpe-scan scan malware.exe\n"
            "  winpe-scan compare file1.exe file2.exe\n"
        ),
    )
    parser.add_argument(
        "-V", "--version",
        action="version",
        version=f"winpe-scan {__version__}",
    )

    sub = parser.add_subparsers(dest="command", help="Available commands")

    # ── info ─────────────────────────────────────────────────────────────
    p_info = sub.add_parser("info", help="Full PE analysis with all sections")
    p_info.add_argument("file", help="PE file to analyze")
    p_info.add_argument("--json", action="store_true", help="Output as JSON")
    p_info.add_argument(
        "-o", "--output", metavar="FILE", help="Write JSON report to file",
    )

    # ── scan ─────────────────────────────────────────────────────────────
    p_scan = sub.add_parser("scan", help="Scan file for threats (info + heuristics)")
    p_scan.add_argument("file", help="PE file to scan")
    p_scan.add_argument("--json", action="store_true", help="Output as JSON")
    p_scan.add_argument(
        "-o", "--output", metavar="FILE", help="Write JSON report to file",
    )
    p_scan.add_argument(
        "-d", "--directory", help="Scan all PE files in a directory",
    )
    p_scan.add_argument(
        "--vt", action="store_true",
        help="Lookup hash on VirusTotal (requires VT_API_KEY env var)",
    )

    # ── strings ──────────────────────────────────────────────────────────
    p_strings = sub.add_parser("strings", help="Extract ASCII/Unicode strings")
    p_strings.add_argument("file", help="PE file")
    p_strings.add_argument(
        "-m", "--min-length", type=int, default=5,
        help="Minimum string length (default: 5)",
    )
    p_strings.add_argument(
        "-f", "--filter", help="Regex filter on extracted strings",
    )
    p_strings.add_argument("--json", action="store_true", help="Output as JSON")

    # ── hash ─────────────────────────────────────────────────────────────
    p_hash = sub.add_parser("hash", help="Compute file hashes")
    p_hash.add_argument("file", help="File to hash")
    p_hash.add_argument("--json", action="store_true", help="Output as JSON")

    # ── headers ──────────────────────────────────────────────────────────
    p_headers = sub.add_parser("headers", help="Display PE header structures")
    p_headers.add_argument("file", help="PE file")
    p_headers.add_argument("--json", action="store_true", help="Output as JSON")

    # ── sections ─────────────────────────────────────────────────────────
    p_sections = sub.add_parser("sections", help="Analyze PE sections")
    p_sections.add_argument("file", help="PE file")
    p_sections.add_argument("--json", action="store_true", help="Output as JSON")

    # ── imports ──────────────────────────────────────────────────────────
    p_imports = sub.add_parser("imports", help="List imports and exports")
    p_imports.add_argument("file", help="PE file")
    p_imports.add_argument("--json", action="store_true", help="Output as JSON")

    # ── compare ──────────────────────────────────────────────────────────
    p_compare = sub.add_parser("compare", help="Compare two PE files")
    p_compare.add_argument("file1", help="First PE file")
    p_compare.add_argument("file2", help="Second PE file")
    p_compare.add_argument("--json", action="store_true", help="Output as JSON")

    # ── sig ──────────────────────────────────────────────────────────────
    p_sig = sub.add_parser("sig", help="Check digital signature info")
    p_sig.add_argument("file", help="PE file")

    return parser


def _load_file(filepath: str) -> bytes | None:
    """Load file contents with error handling."""
    path = Path(filepath)
    if not path.exists():
        print(
            f"{C.RED}[!] File not found: {filepath}{C.RESET}",
            file=sys.stderr,
        )
        return None
    if not path.is_file():
        print(
            f"{C.RED}[!] Not a regular file: {filepath}{C.RESET}",
            file=sys.stderr,
        )
        return None
    try:
        return path.read_bytes()
    except PermissionError:
        print(
            f"{C.RED}[!] Permission denied: {filepath}{C.RESET}",
            file=sys.stderr,
        )
        return None
    except OSError as e:
        print(
            f"{C.RED}[!] Error reading file: {e}{C.RESET}",
            file=sys.stderr,
        )
        return None


def _analyze_file(filepath: str) -> PEAnalysisResult | None:
    """Load, parse, and analyze a single PE file."""
    data = _load_file(filepath)
    if data is None:
        return None

    parser = PEParser(data, filepath)
    result = parser.parse()
    analyze(result)
    return result


def _cmd_info(args: argparse.Namespace) -> int:
    """Execute the info command."""
    result = _analyze_file(args.file)
    if result is None:
        return 1
    if result.error and not result.is_valid_pe:
        print(
            f"{C.RED}[!] {result.error}{C.RESET}",
            file=sys.stderr,
        )
        return 1

    if args.json:
        if args.output:
            data = _result_to_dict(result)
            Path(args.output).write_text(
                json.dumps(data, indent=2, ensure_ascii=False),
            )
            print(
                f"{C.GREEN}[+] Report written to {args.output}{C.RESET}",
            )
        else:
            print_json(result)
    else:
        print_info(result)

    return 0


def _cmd_scan(args: argparse.Namespace) -> int:
    """Execute the scan command."""
    if args.directory:
        return _scan_directory(args.directory, args.json, args.output)

    result = _analyze_file(args.file)
    if result is None:
        return 1

    # VirusTotal lookup
    if args.vt:
        _do_vt_lookup(result)

    if args.json:
        if args.output:
            data = _result_to_dict(result)
            Path(args.output).write_text(
                json.dumps(data, indent=2, ensure_ascii=False),
            )
            print(
                f"{C.GREEN}[+] Report written to {args.output}{C.RESET}",
            )
        else:
            print_json(result)
    else:
        print_info(result)

    return 0


def _scan_directory(
    directory: str,
    as_json: bool,
    output: str | None,
) -> int:
    """Scan all PE files in a directory."""
    path = Path(directory)
    if not path.is_dir():
        print(
            f"{C.RED}[!] Not a directory: {directory}{C.RESET}",
            file=sys.stderr,
        )
        return 1

    pe_extensions = {
        ".exe", ".dll", ".sys", ".ocx", ".cpl", ".drv", ".scr",
    }
    files = [
        f for f in path.iterdir()
        if f.is_file() and f.suffix.lower() in pe_extensions
    ]

    if not files:
        print(f"{C.YELLOW}[!] No PE files found in {directory}{C.RESET}")
        return 0

    print(
        f"{C.CYAN}[*] Scanning {len(files)} "
        f"file(s) in {directory}{C.RESET}\n",
    )

    results = []
    for f in sorted(files):
        result = _analyze_file(str(f))
        if result is not None:
            results.append(result)
            if not as_json:
                print_info(result)

    if as_json:
        all_data = [_result_to_dict(r) for r in results]
        output_str = json.dumps(
            all_data, indent=2, ensure_ascii=False,
        )
        if output:
            Path(output).write_text(output_str)
            print(
                f"{C.GREEN}[+] Report written to {output}{C.RESET}",
            )
        else:
            print(output_str)

    # Summary
    threats = [r for r in results if r.threat_score > 0]
    print(
        f"\n{C.BOLD}Scan complete:{C.RESET} "
        f"{len(results)} file(s) analyzed, "
        f"{len(threats)} with threat indicators"
    )

    return 0


def _cmd_strings(args: argparse.Namespace) -> int:
    """Execute the strings command."""
    data = _load_file(args.file)
    if data is None:
        return 1

    parser = PEParser(data, args.file)
    result = parser.parse()

    strings = result.all_strings
    if args.filter:
        try:
            regex = re.compile(args.filter, re.IGNORECASE)
            strings = [s for s in strings if regex.search(s)]
        except re.error as e:
            print(
                f"{C.RED}[!] Invalid regex: {e}{C.RESET}",
                file=sys.stderr,
            )
            return 1

    # Filter by min length (override parser default if needed)
    if args.min_length != 5:
        strings = [
            s for s in strings if len(s) >= args.min_length
        ]

    if args.json:
        print(json.dumps(
            {"file": args.file, "strings": strings},
            indent=2,
        ))
    else:
        print(
            f"{C.CYAN}[ STRINGS ]{C.RESET}  "
            f"{C.DIM}({len(strings)} found){C.RESET}\n",
        )
        for s in strings:
            print(f"  {C.GREEN}{s}{C.RESET}")

    return 0


def _cmd_hash(args: argparse.Namespace) -> int:
    """Execute the hash command."""
    data = _load_file(args.file)
    if data is None:
        return 1

    import hashlib

    hashes = {
        "MD5": hashlib.md5(data).hexdigest(),  # noqa: S324
        "SHA1": hashlib.sha1(data).hexdigest(),  # noqa: S324
        "SHA256": hashlib.sha256(data).hexdigest(),
        "SHA512": hashlib.sha512(data).hexdigest(),
        "size": len(data),
    }

    if args.json:
        print(json.dumps(hashes, indent=2))
    else:
        print(
            f"\n{C.BRIGHT_CYAN}[ HASHES ]{C.RESET}  "
            f"{C.DIM}\u2014 {args.file}{C.RESET}\n",
        )
        for algo, h in hashes.items():
            if algo == "size":
                print(
                    f"  {C.WHITE}{algo:<8}{C.RESET} "
                    f"{C.CYAN}{h:,} bytes{C.RESET}",
                )
            else:
                print(
                    f"  {C.WHITE}{algo:<8}{C.RESET} "
                    f"{C.YELLOW}{h}{C.RESET}",
                )
        print()

    return 0


def _cmd_headers(args: argparse.Namespace) -> int:
    """Execute the headers command."""
    result = _analyze_file(args.file)
    if result is None:
        return 1

    if args.json:
        print_json(result)
    else:
        # Reuse the info display but only show header sections
        print_info(result)

    return 0


def _cmd_sections(args: argparse.Namespace) -> int:
    """Execute the sections command."""
    result = _analyze_file(args.file)
    if result is None:
        return 1

    if args.json:
        print_json(result)
    else:
        print_info(result)

    return 0


def _cmd_imports(args: argparse.Namespace) -> int:
    """Execute the imports command."""
    result = _analyze_file(args.file)
    if result is None:
        return 1

    if args.json:
        print_json(result)
    else:
        print_info(result)

    return 0


def _cmd_compare(args: argparse.Namespace) -> int:
    """Execute the compare command."""
    r1 = _analyze_file(args.file1)
    r2 = _analyze_file(args.file2)
    if r1 is None or r2 is None:
        return 1

    if args.json:
        data = {
            "file1": _result_to_dict(r1),
            "file2": _result_to_dict(r2),
        }
        print(json.dumps(data, indent=2, ensure_ascii=False))
        return 0

    same_hash = r1.sha256 == r2.sha256
    h1 = r1.sha256
    h2 = r2.sha256

    print(
        f"\n{C.BRIGHT_CYAN}[ COMPARE ]{C.RESET}  "
        f"{C.DIM}{r1.filename} vs {r2.filename}{C.RESET}\n",
    )

    print(f"  {C.WHITE}File Size:{C.RESET}")
    print(
        f"    {C.CYAN}{r1.filename:<30}{C.RESET} "
        f"{r1.file_size:>10,} bytes",
    )
    print(
        f"    {C.CYAN}{r2.filename:<30}{C.RESET} "
        f"{r2.file_size:>10,} bytes",
    )

    print(f"\n  {C.WHITE}SHA256:{C.RESET}")
    print(
        f"    {C.CYAN}{r1.filename:<30}{C.RESET} "
        f"{C.YELLOW}{h1[:32]}...{C.RESET}",
    )
    print(
        f"    {C.CYAN}{r2.filename:<30}{C.RESET} "
        f"{C.YELLOW}{h2[:32]}...{C.RESET}",
    )
    match_color = C.GREEN if same_hash else C.RED
    match_str = "IDENTICAL" if same_hash else "DIFFERENT"
    print(
        f"    {C.WHITE}Match:{C.RESET}  "
        f"{match_color}{C.BOLD}{match_str}{C.RESET}",
    )

    # Sections comparison
    print(f"\n  {C.WHITE}Sections:{C.RESET}")
    print(f"    {r1.filename}: {len(r1.sections)} section(s)")
    print(f"    {r2.filename}: {len(r2.sections)} section(s)")

    # Import comparison
    dll1 = {imp.dll for imp in r1.imports}
    dll2 = {imp.dll for imp in r2.imports}
    common = dll1 & dll2
    only1 = dll1 - dll2
    only2 = dll2 - dll1

    print(f"\n  {C.WHITE}Imports:{C.RESET}")
    print(f"    {r1.filename}: {len(dll1)} DLL(s)")
    print(f"    {r2.filename}: {len(dll2)} DLL(s)")
    if common:
        print(
            f"    {C.GREEN}Common:{C.RESET} "
            f"{', '.join(sorted(common))}",
        )
    if only1:
        print(
            f"    {C.YELLOW}Only in {r1.filename}:{C.RESET} "
            f"{', '.join(sorted(only1))}",
        )
    if only2:
        print(
            f"    {C.YELLOW}Only in {r2.filename}:{C.RESET} "
            f"{', '.join(sorted(only2))}",
        )

    # Risk comparison
    print(f"\n  {C.WHITE}Risk:{C.RESET}")
    print(
        f"    {r1.filename}: {r1.risk_level.value} "
        f"(score: {r1.threat_score})",
    )
    print(
        f"    {r2.filename}: {r2.risk_level.value} "
        f"(score: {r2.threat_score})",
    )
    print()

    return 0


def _cmd_sig(args: argparse.Namespace) -> int:
    """Execute the sig command."""
    print(
        f"\n{C.BRIGHT_CYAN}[ DIGITAL SIGNATURE ]{C.RESET}  "
        f"{C.DIM}\u2014 {args.file}{C.RESET}\n",
    )
    print(
        f"  {C.YELLOW}[!] Digital signature "
        f"verification requires Windows API{C.RESET}",
    )
    print(f"  {C.DIM}On Windows, use one of:{C.RESET}")
    print(
        f"    {C.CYAN}sigcheck.exe -v {args.file}{C.RESET}",
    )
    print(
        f"    {C.CYAN}Get-AuthenticodeSignature "
        f"{args.file}{C.RESET}  (PowerShell)",
    )
    print(
        f"    {C.DIM}Or: Right-click \u2192 Properties "
        f"\u2192 Digital Signatures{C.RESET}\n",
    )

    # Try to detect embedded signatures (PE certificate table)
    data = _load_file(args.file)
    if data:
        # Check for certificate table in data directory
        try:
            from winpe_scan.pe_parser import PEParser

            parser = PEParser(data, args.file)
            result = parser.parse()
            if result.optional_header and result.dos_header:
                # Data directory entry 4 = Security/Certificate
                is_64 = result.optional_header.is_64bit
                pe_offset = result.dos_header.pe_offset
                dd_offset = (
                    pe_offset + 24
                    + (112 if is_64 else 96)
                    + (4 * 8)
                )
                if dd_offset + 8 <= len(data):
                    cert_rva = int.from_bytes(
                        data[dd_offset : dd_offset + 4], "little",
                    )
                    cert_size = int.from_bytes(
                        data[dd_offset + 4 : dd_offset + 8],
                        "little",
                    )
                    if cert_rva > 0 and cert_size > 0:
                        print(
                            f"  {C.GREEN}[+] Certificate "
                            f"table found:{C.RESET}",
                        )
                        print(
                            f"    {C.WHITE}RVA:{C.RESET}  "
                            f"0x{cert_rva:08X}",
                        )
                        print(
                            f"    {C.WHITE}Size:{C.RESET} "
                            f"{cert_size:,} bytes",
                        )
                        print(
                            f"    {C.DIM}(Full verification "
                            f"requires Windows){C.RESET}\n",
                        )
                    else:
                        print(
                            f"  {C.RED}[-] No digital "
                            f"signature detected{C.RESET}\n",
                        )
        except Exception:
            print(
                f"  {C.DIM}(Could not inspect "
                f"certificate table){C.RESET}\n",
            )

    return 0


def _result_to_dict(result: PEAnalysisResult) -> dict[str, Any]:
    """Convert result to dict for JSON serialization."""
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
        ep = result.optional_header.entry_point
        data["entry_point"] = f"0x{ep:08X}"
        ib = result.optional_header.image_base
        data["image_base"] = f"0x{ib:X}"
        data["subsystem"] = result.optional_header.subsystem_str
        data["linker_version"] = (
            result.optional_header.linker_version
        )
    if result.sections:
        data["sections"] = [
            {
                "name": s.name,
                "virtual_address": (
                    f"0x{s.virtual_address:08X}"
                ),
                "virtual_size": s.virtual_size,
                "raw_size": s.raw_size,
                "entropy": s.entropy,
                "flags": s.flags,
            }
            for s in result.sections
        ]
    if result.imports:
        data["imports"] = [
            {"dll": i.dll, "functions": i.functions}
            for i in result.imports
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
                "severity": i.severity.value,
                "category": i.category,
                "description": i.description,
                "evidence": i.evidence,
            }
            for i in result.threat_indicators
        ]
    if result.suspicious_strings:
        data["suspicious_strings"] = result.suspicious_strings
    return data


def _do_vt_lookup(result: Any) -> None:
    """Perform VirusTotal lookup and attach result."""
    from winpe_scan.virustotal import lookup_hash

    print(
        f"  {C.CYAN}[*] Looking up SHA256 on VirusTotal...{C.RESET}",
    )
    vt = lookup_hash(result.sha256)
    result.vt_result = vt

    if vt.error:
        print(f"  {C.YELLOW}[!] VT: {vt.error}{C.RESET}")
    elif vt.found:
        det_color = C.RED if vt.malicious else C.GREEN
        print(
            f"  {det_color}[+] VT: {vt.detection_ratio}"
            f" detections{C.RESET}",
        )
        if vt.names:
            print(
                f"  {C.DIM}    Known as: {vt.names[0]}{C.RESET}",
            )
    else:
        print(f"  {C.DIM}[+] VT: Not found in database{C.RESET}")


def main(argv: Sequence[str] | None = None) -> None:
    """Main entry point."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        print_banner()
        sys.exit(0)

    commands = {
        "info": _cmd_info,
        "scan": _cmd_scan,
        "strings": _cmd_strings,
        "hash": _cmd_hash,
        "headers": _cmd_headers,
        "sections": _cmd_sections,
        "imports": _cmd_imports,
        "compare": _cmd_compare,
        "sig": _cmd_sig,
    }

    handler = commands.get(args.command)
    if handler is None:
        print_banner()
        print(
            f"{C.RED}[!] Unknown command: "
            f"{args.command}{C.RESET}",
            file=sys.stderr,
        )
        sys.exit(1)

    sys.exit(handler(args))


if __name__ == "__main__":
    main()
