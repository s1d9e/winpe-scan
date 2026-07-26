# WinPE-Scan

<p align="center">
  <img src=".assets/logo.svg" width="400" alt="WinPE-Scan">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB.svg?logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/Version-2.0.0-0078D4.svg" alt="Version">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-0078D4.svg" alt="Platform">
  <a href="https://github.com/s1d9e/winpe-scan/actions"><img src="https://github.com/s1d9e/winpe-scan/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/s1d9e/winpe-scan/blob/main/LICENSE"><img src="https://img.shields.io/badge/Code%20Style-Ruff-000000.svg" alt="Ruff"></a>
  <img src="https://img.shields.io/badge/Mypy-strict-964EE8.svg?logo=python&logoColor=white" alt="Mypy">
</p>

> *"Knowledge is power, but analysis is understanding."*

**WinPE-Scan** is a professional-grade static analysis toolkit for Windows Portable Executable (PE) files. Built for malware analysts, reverse engineers, and security researchers.

---

## Disclaimer

> **FOR AUTHORIZED SECURITY RESEARCH AND EDUCATIONAL PURPOSES ONLY**
>
> - Use only on files you are authorized to analyze
> - The author assumes no liability for misuse
> - Respect all applicable laws in your jurisdiction

---

## Quick Start

```bash
git clone https://github.com/s1d9e/winpe-scan.git
cd winpe-scan
pip install -e .
winpe-scan scan malware.exe
```

---

## Live Demo

```
════════════════════════════════════════════════════════════════════════
║  W I N P E - S C A N  v2.0
║  Windows PE Multi-Tool Analyzer
║  For authorized security research only
════════════════════════════════════════════════════════════════════════
  Commands:  info | scan | strings | hash | headers | sections | imports | compare | sig

════════════════════════════════════════════════════════════════════════
  PE ANALYSIS REPORT  -- sample.exe
════════════════════════════════════════════════════════════════════════

  Threat Score:  ██████████████████████████████  100/100 [CRITICAL]

  [ FILE INFO ]
  File:            sample.exe
  Size:            32,768 bytes  (32.0 KB)
  MD5:             974146898bf908e29fe9fa6ef23e0573
  SHA256:          cee2ec8ddcc6c17498992858de60b89d2f18624d...

  [ SECTIONS ]  (3 sections)
  Name       VirtAddr     VirtSize     RawSize      Entropy                   Flags
  .text      0x00001000   0x00003000   0x00003000   █░░░░░░░░░░░░░░░░░░░ 0.53  CODE EXEC READ
  .data      0x00004000   0x00002000   0x00002000   ████████████░░░░░░░░ 4.98  READ WRITE

  [ PACKER DETECTED ]
  Packer:          UPX
  Confidence:      95%

  [ THREAT INDICATORS ]  (21 found)
  [CRITICAL] [YARA] Rule 'Ransomware_Indicators': Potential ransomware behavior
           bitcoin, note
  [CRITICAL] [YARA] Rule 'Process_Hollowing': Process hollowing technique
           write, thread, alloc
  [    HIGH] [PACKER] Detected packer/crypter: UPX
  [    HIGH] [SECTION] Section '.text' is writable + executable (W^X violation)
  [    HIGH] [COMMAND] Suspicious command pattern: certutil -urlcache
  [  MEDIUM] [HARDENING] Missing security mitigations (3)
           Missing: ASLR, CFG, GS Stack Cookie

  [ YARA RULES ]  (6 rules matched)
  [CRITICAL] Rule 'Ransomware_Indicators': Potential ransomware behavior
  [CRITICAL] Rule 'Process_Hollowing': Process injection technique
  [    HIGH] Rule 'Persistence_Scheduled_Task': Scheduled task creation
  [    HIGH] Rule 'Network_C2_Communication': C2 communication patterns
  [    HIGH] Rule 'Data_Exfiltration': Data exfiltration techniques
  [  MEDIUM] Rule 'Living_off_the_Land': LOLBins usage

  ════════════════════════════════════════════════════════════════════
  Analysis complete.  Threat: 21  |  Risk: CRITICAL  |  Entropy: 1.92
  ════════════════════════════════════════════════════════════════════
```

Try it yourself: `python demo.py`

---

## Commands

| Command | Description |
|---------|-------------|
| `info` | Full PE analysis with all sections |
| `scan` | Threat-focused scan with heuristic scoring |
| `strings` | Extract ASCII/Unicode strings with regex filter |
| `hash` | Compute MD5, SHA1, SHA256, SHA512 hashes |
| `headers` | Display PE header structures |
| `sections` | Section analysis with entropy visualization |
| `imports` | Import and export table listing |
| `compare` | Side-by-side comparison of two PE files |
| `sig` | Digital signature inspection |

---

## Features

### Core Analysis
- **PE32 & PE32+** - Full 32-bit and 64-bit support
- **Rich Header** - Decode MSVC toolchain metadata
- **Shannon Entropy** - Statistical randomness measurement with visual bars

### Threat Detection
- **Packer Detection** - UPX, Themida, VMProtect, ASPack, MPRESS, Obsidium, Enigma, MEW, FSG, PECompact
- **Anti-Analysis Detection** - Anti-debug (IsDebuggerPresent, NtQueryInformationProcess...), anti-VM, process injection, privilege escalation, persistence
- **YARA Rules** - 10 built-in detection rules for ransomware, C2, credential theft, LOLBins, data exfiltration
- **Structural Anomalies** - Entry point outside code, W+X sections, missing ASLR/DEP/CFG
- **Overlay Detection** - Data appended after PE image

### Integrations
- **VirusTotal** - Hash lookup via API (`--vt` flag)
- **JSON Export** - Machine-readable reports (`--json -o report.json`)
- **Batch Scanning** - Scan entire directories (`-d /path/`)

---

## Usage

```bash
# Full analysis
winpe-scan info malware.exe

# Threat scan with risk score
winpe-scan scan suspicious.exe

# VirusTotal lookup
VT_API_KEY=your_key winpe-scan scan malware.exe --vt

# Batch scan a directory
winpe-scan scan -d /path/to/samples/

# Extract strings with filter
winpe-scan strings malware.exe --filter "http" --min-length 6

# Compare two files
winpe-scan compare file1.exe file2.exe

# Export JSON report
winpe-scan info malware.exe --json -o report.json

# Run the demo
python demo.py
```

---

## Project Structure

```
winpe-scan/
├── winpe_scan/
│   ├── __init__.py         # Package version
│   ├── __main__.py         # python -m winpe_scan
│   ├── models.py           # Data models & threat constants
│   ├── pe_parser.py        # PE binary parser engine
│   ├── heuristics.py       # Threat detection heuristics
│   ├── yara_rules.py       # Built-in YARA-style rules
│   ├── virustotal.py       # VirusTotal API integration
│   ├── display.py          # Terminal output formatting
│   └── cli.py              # CLI argument parsing
├── tests/
│   └── test_pe_parser.py   # Unit tests (26 tests)
├── demo.py                 # Interactive demo
├── pyproject.toml           # Package configuration
├── requirements.txt         # Runtime dependencies
├── requirements-dev.txt     # Development dependencies
├── .github/workflows/ci.yml # CI pipeline
├── LICENSE
├── LEGAL.md
└── README.md
```

---

## Development

```bash
# Install with dev tools
pip install -e ".[dev]"

# Run tests
pytest

# Lint & format
ruff check .
ruff format .

# Type check
mypy winpe_scan/ --ignore-missing-imports
```

---

## Quality

| Check | Status |
|-------|--------|
| Ruff lint | 0 errors |
| Mypy strict | 0 errors |
| Tests | 26/26 passing |
| CI | GitHub Actions |

---

## Technologies

- **Python 3.10+** - Modern type hints, `from __future__ import annotations`
- **Colorama** - Cross-platform terminal colors
- **Struct** - Native binary parsing
- **Shannon Entropy** - Statistical randomness measurement
- **Built-in YARA** - Pattern-based detection without external deps
- **Zero heavy dependencies** - Fast, portable, auditable

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit with conventional format (`feat:`, `fix:`, `docs:`)
4. Push and open a Pull Request

---

## License

MIT License - see [LICENSE](LICENSE) for details.

---

<p align="center">
  Built by <a href="https://github.com/s1d9e">s1d9e</a> — For authorized security research only
</p>
