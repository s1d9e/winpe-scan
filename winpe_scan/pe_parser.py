"""
PE file parser — handles binary parsing of Portable Executable files.

Supports PE32 and PE32+ (64-bit), Rich header decoding, import/export
directory walking, section analysis with Shannon entropy computation,
and overlay detection.

Copyright (c) 2026 s1d9e — MIT License
"""

from __future__ import annotations

import hashlib
import math
import os
import re
import struct

from winpe_scan.models import (
    MACHINE_TYPES,
    SUBSYSTEM_TYPES,
    DosHeader,
    ExportEntry,
    FileHeader,
    ImportEntry,
    OptionalHeader,
    OverlayInfo,
    PEAnalysisResult,
    PESection,
    RichEntry,
)

DOS_MAGIC = 0x5A4D
PE_SIGNATURE = b"PE\x00\x00"
RICH_MAGIC = b"Rich"
DANS_MAGIC = b"DanS"

SECTION_FLAG_NAMES: dict[int, str] = {
    0x00000020: "CODE",
    0x00000040: "INIT_DATA",
    0x00000080: "UNINIT_DATA",
    0x02000000: "DISCARDABLE",
    0x04000000: "NOT_CACHED",
    0x08000000: "NOT_PAGED",
    0x10000000: "SHARED",
    0x20000000: "EXEC",
    0x40000000: "READ",
    0x80000000: "WRITE",
}

RICH_XOR_KEY = 0x8107485A  # Standard Rich header XOR key


def _read_uint16(data: bytes, offset: int) -> int:
    return int(struct.unpack_from("<H", data, offset)[0])


def _read_uint32(data: bytes, offset: int) -> int:
    return int(struct.unpack_from("<I", data, offset)[0])


def _read_uint64(data: bytes, offset: int) -> int:
    return int(struct.unpack_from("<Q", data, offset)[0])


def _read_cstring(data: bytes, offset: int, max_len: int = 256) -> str:
    end = offset
    limit = min(offset + max_len, len(data))
    while end < limit and data[end] != 0x00:
        end += 1
    return data[offset:end].decode("ascii", errors="ignore")


def shannon_entropy(data: bytes) -> float:
    """Compute Shannon entropy of a byte sequence (0.0-8.0)."""
    length = len(data)
    if length == 0:
        return 0.0

    freq = [0] * 256
    for byte in data:
        freq[byte] += 1

    entropy = 0.0
    for count in freq:
        if count == 0:
            continue
        probability = count / length
        entropy -= probability * math.log2(probability)

    return round(entropy, 4)


class PEParser:
    """Binary parser for Windows PE files."""

    def __init__(self, data: bytes, filepath: str = "") -> None:
        self.data = data
        self.filepath = filepath
        self.filename = os.path.basename(filepath) if filepath else ""
        self.pe_offset: int = 0

    def parse(self) -> PEAnalysisResult:
        """Run full PE parse and return structured result."""
        result = PEAnalysisResult(
            filename=self.filename,
            filepath=self.filepath,
            file_size=len(self.data),
        )

        self._compute_hashes(result)
        self._parse_dos_header(result)

        if not result.is_valid_pe:
            result.error = "Not a valid PE file (missing MZ/PE signature)"
            return result

        self._parse_rich_header(result)
        self._parse_file_header(result)
        self._parse_optional_header(result)
        self._parse_sections(result)

        if result.optional_header and result.optional_header.is_64bit:
            self._parse_imports_64(result)
        else:
            self._parse_imports_32(result)

        self._parse_exports(result)
        self._detect_overlay(result)
        self._extract_strings(result)

        return result

    def _compute_hashes(self, result: PEAnalysisResult) -> None:
        result.md5 = hashlib.md5(self.data).hexdigest()  # noqa: S324
        result.sha1 = hashlib.sha1(self.data).hexdigest()  # noqa: S324
        result.sha256 = hashlib.sha256(self.data).hexdigest()

    def _parse_dos_header(self, result: PEAnalysisResult) -> None:
        if len(self.data) < 64:
            return

        dos = DosHeader()
        dos.magic = _read_uint16(self.data, 0)
        dos.pe_offset = _read_uint32(self.data, 60)

        if dos.magic != DOS_MAGIC:
            return

        self.pe_offset = dos.pe_offset
        if self.pe_offset + 4 > len(self.data):
            return

        if self.data[self.pe_offset : self.pe_offset + 4] != PE_SIGNATURE:
            return

        result.dos_header = dos
        result.is_valid_pe = True

    def _parse_rich_header(self, result: PEAnalysisResult) -> None:
        """Decode the Rich header (XOR-encrypted compid block)."""
        start = self.pe_offset
        rich_pos = self.data.find(RICH_MAGIC, 0, start)
        if rich_pos == -1:
            return

        dans_pos = self.data.find(DANS_MAGIC, 0, rich_pos)
        if dans_pos == -1:
            return

        # The compid block sits between DanS (exclusive) and Rich (exclusive)
        # DanS + 3 dword padding, then pairs of (id, count), terminated by Rich
        block_start = dans_pos + 16  # skip DanS + 3 zero dwords
        block_data = bytearray(self.data[block_start:rich_pos])

        # XOR-decrypt
        key = _read_uint32(self.data, rich_pos + 4)
        for i in range(0, len(block_data) - 3, 4):
            dword = (
                block_data[i]
                | (block_data[i + 1] << 8)
                | (block_data[i + 2] << 16)
                | (block_data[i + 3] << 24)
            )
            dword ^= key
            block_data[i] = dword & 0xFF
            block_data[i + 1] = (dword >> 8) & 0xFF
            block_data[i + 2] = (dword >> 16) & 0xFF
            block_data[i + 3] = (dword >> 24) & 0xFF

        block_bytes = bytes(block_data)

        entries: list[RichEntry] = []
        pos = 0
        while pos + 8 <= len(block_bytes):
            comp_id = _read_uint16(block_bytes, pos)
            build_id = _read_uint16(block_bytes, pos + 2)
            use_count = _read_uint32(block_bytes, pos + 4)
            pos += 8

            if comp_id == 0 and build_id == 0:
                continue

            product_id = (comp_id >> 16) & 0xFFFF
            tool_id = comp_id & 0xFFFF

            entries.append(
                RichEntry(
                    build_id=build_id,
                    product_id=product_id,
                    tool_name=_rich_tool_name(tool_id),
                    tool_build=tool_id,
                    count=use_count,
                )
            )

        result.rich_entries = entries

    def _parse_file_header(self, result: PEAnalysisResult) -> None:
        offset = self.pe_offset + 4
        if offset + 20 > len(self.data):
            return

        fh = FileHeader()
        fh.machine = _read_uint16(self.data, offset)
        fh.machine_str = MACHINE_TYPES.get(fh.machine, f"0x{fh.machine:04X}")
        fh.num_sections = _read_uint16(self.data, offset + 2)
        fh.timestamp = _read_uint32(self.data, offset + 4)
        fh.characteristics = _read_uint16(self.data, offset + 18)
        result.file_header = fh

    def _parse_optional_header(self, result: PEAnalysisResult) -> None:
        offset = self.pe_offset + 24
        if offset + 2 > len(self.data):
            return

        magic = _read_uint16(self.data, offset)
        oh = OptionalHeader()
        oh.magic = magic
        oh.is_64bit = magic == 0x20B

        if magic == 0x10B:  # PE32
            self._parse_optional_header_32(offset, oh)
        elif magic == 0x20B:  # PE32+
            self._parse_optional_header_64(offset, oh)
        else:
            return

        result.optional_header = oh
        result.is_64bit = oh.is_64bit

    def _parse_optional_header_32(self, offset: int, oh: OptionalHeader) -> None:
        if offset + 96 > len(self.data):
            return
        oh.linker_version = f"{self.data[offset + 2]}.{self.data[offset + 3]}"
        oh.size_of_code = _read_uint32(self.data, offset + 4)
        oh.size_of_initialized_data = _read_uint32(self.data, offset + 8)
        oh.size_of_uninitialized_data = _read_uint32(self.data, offset + 12)
        oh.entry_point = _read_uint32(self.data, offset + 16)
        oh.base_of_code = _read_uint32(self.data, offset + 20)
        oh.base_of_data = _read_uint32(self.data, offset + 24)
        oh.image_base = _read_uint32(self.data, offset + 28)
        oh.section_alignment = _read_uint32(self.data, offset + 32)
        oh.file_alignment = _read_uint32(self.data, offset + 36)
        major = _read_uint16(self.data, offset + 40)
        minor = _read_uint16(self.data, offset + 42)
        oh.os_version = f"{major}.{minor}"
        oh.subsystem = _read_uint16(self.data, offset + 68)
        oh.subsystem_str = SUBSYSTEM_TYPES.get(
            oh.subsystem, f"Unknown ({oh.subsystem})"
        )
        oh.dll_characteristics = _read_uint16(self.data, offset + 70)
        oh.size_of_image = _read_uint32(self.data, offset + 56)
        oh.size_of_headers = _read_uint32(self.data, offset + 60)
        oh.checksum = _read_uint32(self.data, offset + 64)

    def _parse_optional_header_64(self, offset: int, oh: OptionalHeader) -> None:
        if offset + 112 > len(self.data):
            return
        oh.linker_version = f"{self.data[offset + 2]}.{self.data[offset + 3]}"
        oh.size_of_code = _read_uint32(self.data, offset + 4)
        oh.size_of_initialized_data = _read_uint32(self.data, offset + 8)
        oh.size_of_uninitialized_data = _read_uint32(self.data, offset + 12)
        oh.entry_point = _read_uint32(self.data, offset + 16)
        oh.base_of_code = _read_uint32(self.data, offset + 20)
        oh.image_base = _read_uint64(self.data, offset + 24)
        oh.section_alignment = _read_uint32(self.data, offset + 32)
        oh.file_alignment = _read_uint32(self.data, offset + 36)
        major = _read_uint16(self.data, offset + 40)
        minor = _read_uint16(self.data, offset + 42)
        oh.os_version = f"{major}.{minor}"
        oh.subsystem = _read_uint16(self.data, offset + 88)
        oh.subsystem_str = SUBSYSTEM_TYPES.get(
            oh.subsystem, f"Unknown ({oh.subsystem})"
        )
        oh.dll_characteristics = _read_uint16(self.data, offset + 90)
        oh.size_of_image = _read_uint32(self.data, offset + 56)
        oh.size_of_headers = _read_uint32(self.data, offset + 60)
        oh.checksum = _read_uint32(self.data, offset + 64)

    def _parse_sections(self, result: PEAnalysisResult) -> None:
        if not result.file_header:
            return

        is_64bit = (
            result.optional_header is not None
            and result.optional_header.is_64bit
        )
        opt_hdr_size = 24 + (240 if is_64bit else 96)
        offset = self.pe_offset + opt_hdr_size

        sections: list[PESection] = []
        for i in range(result.file_header.num_sections):
            off = offset + (i * 40)
            if off + 40 > len(self.data):
                break

            sec = PESection()
            raw_name = self.data[off : off + 8].rstrip(b"\x00")
            sec.name = raw_name.decode("ascii", errors="replace")
            sec.virtual_size = _read_uint32(self.data, off + 8)
            sec.virtual_address = _read_uint32(self.data, off + 12)
            sec.raw_size = _read_uint32(self.data, off + 16)
            sec.raw_offset = _read_uint32(self.data, off + 20)
            sec.characteristics = _read_uint32(self.data, off + 36)

            for flag_bit, flag_name in SECTION_FLAG_NAMES.items():
                if sec.characteristics & flag_bit:
                    sec.flags.append(flag_name)

            if sec.raw_size > 0 and sec.raw_offset > 0:
                data_start = sec.raw_offset
                data_end = min(data_start + sec.raw_size, len(self.data))
                if data_start < len(self.data):
                    sec.entropy = shannon_entropy(
                        self.data[data_start:data_end]
                    )

            sections.append(sec)

        result.sections = sections

    def _rva_to_offset(self, rva: int, sections: list[PESection]) -> int:
        """Convert Relative Virtual Address to file offset."""
        for sec in sections:
            if sec.virtual_address <= rva < sec.virtual_address + sec.virtual_size:
                return rva - sec.virtual_address + sec.raw_offset
        return 0

    def _parse_imports_32(self, result: PEAnalysisResult) -> None:
        """Parse imports for PE32 (32-bit) — Import Directory at index 1."""
        if not result.optional_header:
            return

        # Data directory entry 1 (Import Directory) offset for PE32
        dir_offset = self.pe_offset + 24 + 96 + (1 * 8)
        if dir_offset + 8 > len(self.data):
            return

        import_rva = _read_uint32(self.data, dir_offset)
        if import_rva == 0:
            return

        sections = result.sections or []
        off = self._rva_to_offset(import_rva, sections)
        if off == 0:
            return

        imports: list[ImportEntry] = []
        seen_dlls: set[str] = set()
        pos = off

        while pos + 20 <= len(self.data):
            name_rva = _read_uint32(self.data, pos + 12)
            ilt_rva = _read_uint32(self.data, pos)
            if name_rva == 0 and ilt_rva == 0:
                break

            dll_offset = self._rva_to_offset(name_rva, sections)
            if dll_offset == 0:
                pos += 20
                continue

            dll_name = _read_cstring(self.data, dll_offset).lower()
            if not dll_name or dll_name in seen_dlls:
                pos += 20
                continue

            seen_dlls.add(dll_name)
            funcs = self._read_ilt_32(ilt_rva, sections)
            imports.append(ImportEntry(dll=dll_name, functions=funcs[:50]))
            pos += 20

        result.imports = imports

    def _read_ilt_32(self, ilt_rva: int, sections: list[PESection]) -> list[str]:
        """Read Import Lookup Table entries for PE32."""
        funcs: list[str] = []
        off = self._rva_to_offset(ilt_rva, sections)
        if off == 0:
            return funcs

        pos = off
        while pos + 4 <= len(self.data):
            entry = _read_uint32(self.data, pos)
            if entry == 0:
                break
            if entry & 0x80000000:
                funcs.append(f"Ordinal#{entry & 0xFFFF}")
            else:
                hint_rva = entry & 0x7FFFFFFF
                name_off = self._rva_to_offset(hint_rva + 2, sections)
                if name_off > 0:
                    name = _read_cstring(self.data, name_off)
                    if name:
                        funcs.append(name)
            pos += 4

        return funcs

    def _parse_imports_64(self, result: PEAnalysisResult) -> None:
        """Parse imports for PE32+ (64-bit) — uses 8-byte ILT entries."""
        if not result.optional_header:
            return

        # Data directory entry 1 (Import Directory) for PE32+
        dir_offset = self.pe_offset + 24 + 112 + (1 * 8)
        if dir_offset + 8 > len(self.data):
            return

        import_rva = _read_uint32(self.data, dir_offset)
        if import_rva == 0:
            return

        sections = result.sections or []
        off = self._rva_to_offset(import_rva, sections)
        if off == 0:
            return

        imports: list[ImportEntry] = []
        seen_dlls: set[str] = set()
        pos = off

        while pos + 20 <= len(self.data):
            name_rva = _read_uint32(self.data, pos + 12)
            ilt_rva = _read_uint32(self.data, pos)
            if name_rva == 0 and ilt_rva == 0:
                break

            dll_offset = self._rva_to_offset(name_rva, sections)
            if dll_offset == 0:
                pos += 20
                continue

            dll_name = _read_cstring(self.data, dll_offset).lower()
            if not dll_name or dll_name in seen_dlls:
                pos += 20
                continue

            seen_dlls.add(dll_name)
            funcs = self._read_ilt_64(ilt_rva, sections)
            imports.append(ImportEntry(dll=dll_name, functions=funcs[:50]))
            pos += 20

        result.imports = imports

    def _read_ilt_64(self, ilt_rva: int, sections: list[PESection]) -> list[str]:
        """Read Import Lookup Table entries for PE32+ (8-byte entries)."""
        funcs: list[str] = []
        off = self._rva_to_offset(ilt_rva, sections)
        if off == 0:
            return funcs

        pos = off
        while pos + 8 <= len(self.data):
            entry = _read_uint64(self.data, pos)
            if entry == 0:
                break
            if entry & 0x8000000000000000:
                funcs.append(f"Ordinal#{entry & 0xFFFF}")
            else:
                hint_rva = entry & 0x7FFFFFFF
                name_off = self._rva_to_offset(hint_rva + 2, sections)
                if name_off > 0:
                    name = _read_cstring(self.data, name_off)
                    if name:
                        funcs.append(name)
            pos += 8

        return funcs

    def _parse_exports(self, result: PEAnalysisResult) -> None:
        """Parse Export Directory Table."""
        if not result.optional_header:
            return

        # Data directory entry 0 (Export Directory)
        dir_offset = (
            self.pe_offset + 24
            + (112 if result.optional_header.is_64bit else 96)
        )
        if dir_offset + 8 > len(self.data):
            return

        export_rva = _read_uint32(self.data, dir_offset)
        if export_rva == 0:
            return

        sections = result.sections or []
        off = self._rva_to_offset(export_rva, sections)
        if off == 0 or off + 40 > len(self.data):
            return

        num_names = _read_uint32(self.data, off + 24)
        ordinal_base = _read_uint32(self.data, off + 16)
        name_ptr_rva = _read_uint32(self.data, off + 32)

        name_ptr_off = (
            self._rva_to_offset(name_ptr_rva, sections)
            if name_ptr_rva
            else 0
        )

        exports: list[ExportEntry] = []
        for i in range(min(num_names, 500)):
            if name_ptr_off == 0 or name_ptr_off + i * 4 + 4 > len(self.data):
                break
            entry_name_rva = _read_uint32(self.data, name_ptr_off + i * 4)
            entry_name_off = self._rva_to_offset(entry_name_rva, sections)
            if entry_name_off > 0:
                name = _read_cstring(self.data, entry_name_off)
                if name:
                    exports.append(
                        ExportEntry(ordinal=ordinal_base + i, name=name)
                    )

        result.exports = exports

    def _detect_overlay(self, result: PEAnalysisResult) -> None:
        """Detect data appended after the PE image."""
        if not result.file_header or not result.sections:
            return

        pe_end = 0
        for sec in result.sections:
            end = sec.raw_offset + sec.raw_size
            if end > pe_end:
                pe_end = end

        # Account for headers
        if result.optional_header and result.optional_header.size_of_headers > 0:
            hdr_end = result.optional_header.size_of_headers
            pe_end = max(pe_end, hdr_end)

        if pe_end < len(self.data):
            overlay_data = self.data[pe_end:]
            result.overlay = OverlayInfo(
                present=True,
                offset=pe_end,
                size=len(overlay_data),
                md5=hashlib.md5(overlay_data).hexdigest(),  # noqa: S324
            )

    def _extract_strings(self, result: PEAnalysisResult) -> None:
        """Extract ASCII and Unicode strings from the binary."""
        min_len = 5
        strings_set: set[str] = set()

        # ASCII strings
        ascii_pattern = re.compile(
            rb"(?:[\x20-\x7e]{" + str(min_len).encode() + rb",})"
        )
        for match in ascii_pattern.finditer(self.data):
            s = match.group(0).decode("ascii", errors="ignore")
            if len(s) >= min_len:
                strings_set.add(s)

        # Unicode (UTF-16LE) strings
        unicode_pattern = re.compile(
            rb"(?:[\x20-\x7e]\x00){" + str(min_len).encode() + rb",}"
        )
        for match in unicode_pattern.finditer(self.data):
            s = match.group(0).decode("utf-16-le", errors="ignore")
            if len(s) >= min_len:
                strings_set.add(s)

        result.all_strings = sorted(strings_set, key=len, reverse=True)


def _rich_tool_name(tool_id: int) -> str:
    """Map Rich header tool IDs to compiler/linker names."""
    known_tools: dict[int, str] = {
        0x0001: "Import0",
        0x0002: "Linker510",
        0x0003: "Masm512",
        0x0004: "Linker600",
        0x0006: "Export630",
        0x0007: "Implib630",
        0x0009: "Linker610",
        0x000B: "Masm611",
        0x000C: "ResourceCompiler612",
        0x000E: "Import009",
        0x000F: "Compiler614",
        0x0010: "Export615",
        0x0012: "Implib616",
        0x0013: "Compiler617",
        0x0014: "Implib618",
        0x0015: "Compiler619",
        0x0016: "Compiler620",
        0x0018: "ResourceCompiler622",
        0x0019: "Linker623",
        0x001C: "Linker625",
        0x001D: "Compiler626",
        0x001F: "Linker628",
        0x0020: "Compiler629",
        0x0021: "Implib631",
        0x0022: "Compiler632",
        0x0023: "Compiler633",
        0x0024: "Linker634",
        0x0025: "Compiler635",
        0x0026: "Masm636",
        0x0027: "ResourceCompiler637",
        0x0029: "Masm638",
        0x002C: "Compiler641",
        0x002E: "Compiler643",
        0x002F: "ResourceCompiler644",
        0x0030: "Linker650",
        0x0031: "ResourceCompiler651",
        0x0032: "ResourceCompiler652",
        0x0034: "Masm662",
        0x0035: "Implib672",
        0x0036: "Compiler700",
        0x0037: "Compiler710",
        0x0038: "Linker712",
        0x0039: "Masm713",
        0x003B: "Linker715",
        0x003C: "Implib716",
        0x003E: "ResourceCompiler720",
        0x003F: "Compiler800",
        0x0040: "Compiler810",
        0x0041: "Linker812",
        0x0042: "ResourceCompiler813",
        0x0043: "Implib814",
        0x0044: "Compiler816",
        0x0045: "Compiler818",
        0x0046: "Masm819",
        0x0047: "ResourceCompiler820",
        0x0048: "Linker822",
        0x0049: "Compiler900",
        0x004A: "ResourceCompiler900",
        0x004B: "Linker910",
        0x004C: "ResourceCompiler910",
        0x004D: "Implib920",
        0x004E: "Compiler930",
        0x004F: "ResourceCompiler930",
        0x0050: "Compiler940",
        0x0051: "ResourceCompiler940",
        0x0052: "Compiler950",
        0x0053: "Compiler960",
        0x0054: "Linker1000",
        0x0055: "Compiler1100",
        0x0056: "Linker1100",
        0x0057: "Compiler1200",
        0x0058: "Compiler1210",
        0x0059: "Linker1210",
        0x005A: "Compiler1220",
        0x005B: "Linker1220",
        0x005C: "Compiler1400",
        0x005D: "Compiler1410",
        0x005E: "Linker1410",
        0x005F: "Compiler1416",
        0x0060: "Compiler1420",
        0x0061: "Compiler1424",
        0x0062: "Compiler1428",
        0x0063: "Compiler1429",
        0x0064: "Compiler1430",
        0x0065: "Compiler1432",
        0x0066: "Compiler1436",
        0x0067: "Compiler1438",
        0x0068: "Masm1400",
        0x0069: "Masm1410",
        0x006A: "Masm1416",
        0x006B: "Masm1420",
        0x006C: "Masm1424",
        0x006D: "Masm1428",
        0x006E: "Masm1429",
        0x006F: "Masm1430",
        0x0070: "Masm1432",
        0x0071: "Masm1436",
        0x0072: "Masm1438",
        0x0083: "Compiler1500",
        0x0084: "Linker1500",
        0x0085: "Masm1500",
        0x0086: "Compiler1600",
        0x0087: "Linker1600",
        0x0088: "Masm1600",
        0x0090: "Compiler1700",
        0x0091: "Linker1700",
        0x0092: "Compiler1800",
        0x0093: "Compiler1800_X64",
        0x0094: "Compiler1800_ARM",
        0x0095: "Linker1800",
        0x0096: "Masm1800",
        0x0097: "Compiler1900",
        0x0098: "Compiler1900_X64",
        0x0099: "Compiler1900_ARM",
        0x009A: "Compiler1900_ARM64",
        0x009B: "Linker1900",
        0x009C: "Masm1900",
        0x009D: "Compiler1910",
        0x009E: "Compiler1912",
        0x009F: "Compiler1914",
        0x00A0: "Compiler1915",
        0x00A1: "Compiler1916",
        0x00A2: "Compiler1920",
        0x00A3: "Compiler1924",
        0x00A4: "Compiler1925",
        0x00A5: "Compiler1926",
        0x00A6: "Compiler1927",
        0x00A7: "Compiler1928",
        0x00A8: "Compiler1929",
        0x00A9: "Compiler1930",
        0x00AA: "Compiler1931",
        0x00AB: "Compiler1932",
        0x00AC: "Compiler1933",
        0x00AD: "Compiler1934",
        0x00AE: "Compiler1935",
        0x00AF: "Compiler1936",
        0x00B0: "Compiler1937",
        0x00B1: "Compiler1938",
        0x00B2: "Compiler1939",
        0x00B3: "Compiler1940",
        0x00B4: "Compiler1941",
        0x00B5: "Compiler1942",
        0x00B6: "Compiler1943",
        0x00B7: "Compiler1944",
        0x00B8: "Compiler1945",
        0x00B9: "Compiler1946",
        0x00BA: "Compiler1947",
        0x00BB: "Compiler1948",
        0x00BC: "Compiler1949",
        0x00BD: "Compiler1950",
        0x00BE: "Compiler1951",
        0x00BF: "Compiler1952",
        0x00C0: "Compiler1953",
        0x00C1: "Compiler1954",
        0x00C2: "Compiler1955",
        0x00C3: "Compiler1956",
    }
    return known_tools.get(tool_id, f"Unknown(0x{tool_id:04X})")
