"""Tests for the PE parser and heuristics engine."""

from __future__ import annotations

import struct

from winpe_scan.models import PEAnalysisResult
from winpe_scan.pe_parser import PEParser, shannon_entropy

# ─── Minimal PE binary builder ────────────────────────────────────────────


def _build_minimal_pe(
    *,
    is_64: bool = False,
    sections: list[dict] | None = None,
    imports: list[str] | None = None,
) -> bytes:
    """Build a minimal but valid PE binary for testing."""
    data = bytearray(4096)

    # DOS header
    struct.pack_into("<H", data, 0, 0x5A4D)  # e_magic = MZ
    struct.pack_into("<I", data, 60, 64)  # e_lfanew = offset to PE

    # PE signature at offset 64
    struct.pack_into("<4s", data, 64, b"PE\x00\x00")

    # COFF File Header (20 bytes) at offset 68
    machine = 0x8664 if is_64 else 0x014C
    num_sections = len(sections) if sections else 1
    struct.pack_into("<H", data, 68, machine)
    struct.pack_into("<H", data, 70, num_sections)
    struct.pack_into("<I", data, 72, 0x60000000)  # timestamp
    opt_hdr_size = 240 if is_64 else 96
    struct.pack_into("<H", data, 78, opt_hdr_size)  # SizeOfOptionalHeader
    struct.pack_into("<H", data, 82, 0x0022)  # Characteristics

    # Optional Header
    opt_offset = 88
    magic = 0x20B if is_64 else 0x10B
    struct.pack_into("<H", data, opt_offset, magic)
    struct.pack_into("<I", data, opt_offset + 16, 0x1000)  # AddressOfEntryPoint
    if is_64:
        struct.pack_into("<Q", data, opt_offset + 24, 0x140000000)  # ImageBase
        struct.pack_into("<I", data, opt_offset + 56, 0x10000)  # SizeOfImage
        struct.pack_into("<I", data, opt_offset + 60, 0x200)  # SizeOfHeaders
        struct.pack_into("<H", data, opt_offset + 88, 3)  # Subsystem = CUI
        struct.pack_into("<H", data, opt_offset + 90, 0x0160)  # DllCharacteristics (ASLR+DEP+CFG)
    else:
        struct.pack_into("<I", data, opt_offset + 28, 0x00400000)  # ImageBase
        struct.pack_into("<I", data, opt_offset + 56, 0x10000)  # SizeOfImage
        struct.pack_into("<I", data, opt_offset + 60, 0x200)  # SizeOfHeaders
        struct.pack_into("<H", data, opt_offset + 68, 3)  # Subsystem
        struct.pack_into("<H", data, opt_offset + 70, 0x0160)  # DllCharacteristics

    # Section headers start after optional header
    sec_offset = opt_offset + opt_hdr_size
    if sections is None:
        sections = [{"name": ".text", "vsize": 0x1000, "rsize": 0x1000, "chars": 0x60000020}]

    for i, sec in enumerate(sections):
        off = sec_offset + (i * 40)
        name = sec["name"][:8].encode("ascii").ljust(8, b"\x00")
        data[off : off + 8] = name
        struct.pack_into("<I", data, off + 8, sec.get("vsize", 0x1000))
        struct.pack_into("<I", data, off + 12, 0x1000 + i * 0x1000)  # VirtualAddress
        struct.pack_into("<I", data, off + 16, sec.get("rsize", 0x1000))
        struct.pack_into("<I", data, off + 20, 0x200 + i * 0x1000)  # PointerToRawData
        struct.pack_into("<I", data, off + 36, sec.get("chars", 0x60000020))

    return bytes(data)


def _build_pe_with_imports(dll_names: list[str]) -> bytes:
    """Build a PE with a simple import table."""
    data = bytearray(8192)

    # DOS header
    struct.pack_into("<H", data, 0, 0x5A4D)
    struct.pack_into("<I", data, 60, 64)
    struct.pack_into("<4s", data, 64, b"PE\x00\x00")

    # COFF
    struct.pack_into("<H", data, 68, 0x014C)  # i386
    struct.pack_into("<H", data, 70, 1)  # 1 section
    struct.pack_into("<H", data, 78, 96)  # OptHeader size

    # Opt Header
    opt_off = 88
    struct.pack_into("<H", data, opt_off, 0x10B)
    struct.pack_into("<I", data, opt_off + 16, 0x1000)
    struct.pack_into("<I", data, opt_off + 28, 0x00400000)
    struct.pack_into("<I", data, opt_off + 56, 0x10000)
    struct.pack_into("<I", data, opt_off + 60, 0x200)
    struct.pack_into("<H", data, opt_off + 68, 3)

    # Data Directory entry 1 (Import Directory) at offset opt_off + 96 + 8
    # For PE32: dd[1] is at opt_off + 96 + 8 = opt_off + 104
    dd_import_rva = 0x2000
    dd_import_size = len(dll_names) * 20 + 20  # Rough estimate
    struct.pack_into("<I", data, opt_off + 104, dd_import_rva)
    struct.pack_into("<I", data, opt_off + 108, dd_import_size)

    # Section: .text at 0x1000, raw at 0x200
    sec_off = 88 + 96
    data[sec_off : sec_off + 8] = b".text\x00\x00\x00"
    struct.pack_into("<I", data, sec_off + 8, 0x2000)  # VirtualSize
    struct.pack_into("<I", data, sec_off + 12, 0x1000)  # VirtualAddress
    struct.pack_into("<I", data, sec_off + 16, 0x2000)  # RawSize
    struct.pack_into("<I", data, sec_off + 20, 0x200)  # PointerToRawData
    struct.pack_into("<I", data, sec_off + 36, 0x60000020)  # Chars

    # Build import directory at file offset 0x200 (rva 0x1000 mapped at raw 0x200)
    # Actually, let's place import dir at a known raw offset
    import_dir_offset = 0x1200  # raw offset within .text
    import_dir_rva = 0x2200  # corresponding RVA (0x1000 + 0x1200)

    struct.pack_into("<I", data, opt_off + 104, import_dir_rva)

    pos = import_dir_offset
    for i, dll in enumerate(dll_names):
        # ImportDirectoryEntry
        # OriginalFirstThunk, TimeDateStamp, ForwarderChain, Name, FirstThunk
        name_str = dll.encode("ascii") + b"\x00"
        name_offset = import_dir_offset + (len(dll_names) + 1) * 20 + i * len(name_str)
        name_rva = 0x1000 + name_offset  # RVA = section VA + (raw - raw_offset)

        struct.pack_into("<I", data, pos, 0)  # ILT RVA (0 = null terminated)
        struct.pack_into("<I", data, pos + 8, 0)  # Name RVA
        # We'll fake name_rva since this is a minimal test
        struct.pack_into("<I", data, pos + 12, name_rva)
        struct.pack_into("<I", data, pos + 16, 0x1000 + pos - import_dir_offset)  # FirstThunk
        pos += 20

    # Null terminator entry
    for field_offset in range(5):
        struct.pack_into("<I", data, pos + field_offset * 4, 0)
    pos += 20

    # Write DLL names
    for _idx, dll in enumerate(dll_names):
        name_bytes = dll.encode("ascii") + b"\x00"
        data[pos : pos + len(name_bytes)] = name_bytes
        pos += len(name_bytes)

    return bytes(data)


# ─── Tests ────────────────────────────────────────────────────────────────


class TestShannonEntropy:
    """Tests for the Shannon entropy function."""

    def test_empty_data(self) -> None:
        assert shannon_entropy(b"") == 0.0

    def test_uniform_bytes(self) -> None:
        # All same byte → entropy = 0
        assert shannon_entropy(b"\x00" * 100) == 0.0

    def test_maximal_entropy(self) -> None:
        # Perfectly distributed → entropy close to 8.0
        data = bytes(range(256))
        entropy = shannon_entropy(data)
        assert entropy > 7.9

    def test_known_value(self) -> None:
        # "Hello World" has known entropy
        data = b"Hello World"
        entropy = shannon_entropy(data)
        assert 2.0 < entropy < 4.0

    def test_returns_float(self) -> None:
        result = shannon_entropy(b"test data")
        assert isinstance(result, float)


class TestPEParser:
    """Tests for the PE parser."""

    def test_invalid_file_too_small(self) -> None:
        parser = PEParser(b"MZ")
        result = parser.parse()
        assert result.is_valid_pe is False
        assert result.error is not None

    def test_invalid_magic(self) -> None:
        data = b"\x00" * 256
        parser = PEParser(data)
        result = parser.parse()
        assert result.is_valid_pe is False

    def test_valid_minimal_pe(self) -> None:
        data = _build_minimal_pe()
        parser = PEParser(data, "test.exe")
        result = parser.parse()
        assert result.is_valid_pe is True
        assert result.filename == "test.exe"
        assert result.file_size == 4096

    def test_hash_computation(self) -> None:
        data = _build_minimal_pe()
        parser = PEParser(data)
        result = parser.parse()
        assert len(result.md5) == 32
        assert len(result.sha1) == 40
        assert len(result.sha256) == 64

    def test_32bit_detection(self) -> None:
        data = _build_minimal_pe(is_64=False)
        parser = PEParser(data)
        result = parser.parse()
        assert result.is_64bit is False
        assert result.optional_header is not None
        assert result.optional_header.is_64bit is False

    def test_64bit_detection(self) -> None:
        data = _build_minimal_pe(is_64=True)
        parser = PEParser(data)
        result = parser.parse()
        assert result.is_64bit is True
        assert result.optional_header is not None
        assert result.optional_header.is_64bit is True

    def test_sections_parsed(self) -> None:
        data = _build_minimal_pe()
        parser = PEParser(data)
        result = parser.parse()
        assert len(result.sections) >= 1
        assert result.sections[0].name == ".text"

    def test_custom_sections(self) -> None:
        sections = [
            {"name": ".text", "vsize": 0x1000, "rsize": 0x1000, "chars": 0x60000020},
            {"name": ".data", "vsize": 0x500, "rsize": 0x500, "chars": 0xC0000040},
        ]
        data = _build_minimal_pe(sections=sections)
        parser = PEParser(data)
        result = parser.parse()
        assert len(result.sections) == 2
        assert result.sections[0].name == ".text"
        assert result.sections[1].name == ".data"

    def test_section_flags(self) -> None:
        data = _build_minimal_pe()
        parser = PEParser(data)
        result = parser.parse()
        flags = result.sections[0].flags
        assert "CODE" in flags
        assert "EXEC" in flags
        assert "READ" in flags

    def test_section_entropy(self) -> None:
        data = _build_minimal_pe()
        parser = PEParser(data)
        result = parser.parse()
        # Minimal PE has mostly zeros → low entropy
        assert result.sections[0].entropy < 2.0

    def test_file_header(self) -> None:
        data = _build_minimal_pe(is_64=False)
        parser = PEParser(data)
        result = parser.parse()
        assert result.file_header is not None
        assert result.file_header.machine_str == "I386"
        assert result.file_header.num_sections == 1

    def test_strings_extraction(self) -> None:
        data = bytearray(_build_minimal_pe())
        # Insert a visible ASCII string
        test_string = b"Hello from test binary!"
        data[0x1800:0x1800 + len(test_string)] = test_string
        parser = PEParser(bytes(data))
        result = parser.parse()
        assert any("Hello from test binary" in s for s in result.all_strings)

    def test_no_overlay(self) -> None:
        data = _build_minimal_pe()
        parser = PEParser(data)
        result = parser.parse()
        # In a minimal PE with data filling the full file, overlay might not exist
        # Just verify the field exists
        assert result.overlay is None or result.overlay.present is False


class TestPEParserImports:
    """Tests for import parsing."""

    def test_empty_imports_on_minimal_pe(self) -> None:
        data = _build_minimal_pe()
        parser = PEParser(data)
        result = parser.parse()
        # Minimal PE without import dir → empty imports
        assert isinstance(result.imports, list)


class TestHeuristics:
    """Tests for the heuristics engine."""

    def test_imports_from_winpe_scan_heuristics(self) -> None:
        from winpe_scan.heuristics import analyze

        data = _build_minimal_pe()
        parser = PEParser(data)
        result = parser.parse()
        analyze(result)

        # Should return a valid result
        assert isinstance(result.threat_indicators, list)
        assert isinstance(result.threat_score, int)
        assert 0 <= result.threat_score <= 100

    def test_clean_file_low_score(self) -> None:
        from winpe_scan.heuristics import analyze

        data = _build_minimal_pe(is_64=False)
        parser = PEParser(data, "clean.exe")
        result = parser.parse()
        analyze(result)

        # A minimal clean PE should have low or zero threat score
        assert result.threat_score <= 30

    def test_risk_level_property(self) -> None:
        from winpe_scan.heuristics import analyze

        data = _build_minimal_pe()
        parser = PEParser(data)
        result = parser.parse()
        analyze(result)
        assert result.risk_level.value in ("CLEAN", "LOW", "MEDIUM", "HIGH", "CRITICAL")


class TestModels:
    """Tests for data models."""

    def test_threat_score_no_indicators(self) -> None:
        result = PEAnalysisResult()
        assert result.threat_score == 0

    def test_risk_level_clean(self) -> None:
        result = PEAnalysisResult()
        assert result.risk_level.value == "CLEAN"

    def test_entropy_score_no_sections(self) -> None:
        result = PEAnalysisResult()
        assert result.entropy_score == 0.0

    def test_entropy_score_weighted(self) -> None:
        from winpe_scan.models import PESection

        result = PEAnalysisResult(
            sections=[
                PESection(name=".text", raw_size=1000, entropy=6.5),
                PESection(name=".data", raw_size=1000, entropy=3.0),
            ]
        )
        expected = (6.5 * 1000 + 3.0 * 1000) / 2000
        assert result.entropy_score == round(expected, 2)
