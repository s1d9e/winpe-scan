<p align="center">
  <h1 align="center">WinPE-Scan</h1>
  <p align="center">Professional static analysis toolkit for Windows PE files</p>
</p>

<p align="center">
  <a href="https://github.com/s1d9e/winpe-scan/actions"><img src="https://github.com/s1d9e/winpe-scan/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB.svg?logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-0078D4.svg" alt="Platform">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/github/license/s1d9e/winpe-scan" alt="License">
  <img src="https://img.shields.io/github/stars/s1d9e/winpe-scan?style=social" alt="Stars">
  <img src="https://img.shields.io/github/forks/s1d9e/winpe-scan?style=social" alt="Forks">
  <img src="https://img.shields.io/github/watchers/s1d9e/winpe-scan?style=social" alt="Watchers">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Ruff-0__errors-000000.svg" alt="Ruff">
  <img src="https://img.shields.io/badge/Mypy-0__errors-964EE8.svg" alt="Mypy">
  <img src="https://img.shields.io/badge/Tests-26%2F26-2ECC71.svg" alt="Tests">
  <img src="https://img.shields.io/badge/Code%20Size-4k%20lines-blue.svg" alt="Code Size">
  <img src="https://img.shields.io/github/last-commit/s1d9e/winpe-scan" alt="Last Commit">
  <img src="https://img.shields.io/github/issues/s1d9e/winpe-scan" alt="Issues">
  <img src="https://img.shields.io/github/issues-pr/s1d9e/winpe-scan" alt="PRs">
  <img src="https://img.shields.io/badge/PRs-Welcome-brightgreen.svg" alt="PRs Welcome">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Dependencies-Zero-orange.svg" alt="Zero Dependencies">
  <img src="https://img.shields.io/badge/PE32-Supported-0078D4.svg" alt="PE32">
  <img src="https://img.shields.io/badge/PE32%2B-Supported-0078D4.svg" alt="PE32+">
  <img src="https://img.shields.io/badge/YARA-10__rules-E74C3C.svg" alt="YARA Rules">
  <img src="https://img.shields.io/badge/Packers-10%2B-E67E22.svg" alt="Packer Detection">
  <img src="https://img.shields.io/badge/VirusTotal-Integration-3498DB.svg" alt="VirusTotal">
  <img src="https://img.shields.io/badge/Security-Tool-red.svg" alt="Security">
  <img src="https://img.shields.io/badge/Made%20with-Python-FFD43B.svg?logo=python&logoColor=white" alt="Made with Python">
</p>

---

**WinPE-Scan** analyzes Windows executables (.exe, .dll, .sys) and detects malware indicators — packers, injection techniques, suspicious APIs, YARA patterns, and more. Zero heavy dependencies.

---

## Quick Start

```bash
git clone https://github.com/s1d9e/winpe-scan.git
cd winpe-scan
pip install -e .
winpe-scan scan malware.exe
```

---

## Demo

```
  Threat Score:  ██████████████████████████████  100/100 [CRITICAL]

  [ FILE INFO ]
  File:            sample.exe
  Size:            32,768 bytes
  SHA256:          cee2ec8ddcc6c17498992858de60b89d...

  [ SECTIONS ]  (3 sections)
  Name       VirtAddr     Entropy                   Flags
  .text      0x00001000   █░░░░░░░░░░░░░░░░░░░ 0.53  CODE EXEC READ WRITE
  .data      0x00004000   ████████████░░░░░░░░ 4.98  READ WRITE

  [ PACKER DETECTED ]
  Packer:          UPX
  Confidence:      95%

  [ THREAT INDICATORS ]  (21 found)
  [CRITICAL] [YARA] Ransomware behavior — bitcoin, note
  [CRITICAL] [YARA] Process hollowing — write, thread, alloc
  [    HIGH] [PACKER] UPX detected
  [    HIGH] [SECTION] .text is writable + executable
  [    HIGH] [COMMAND] certutil -urlcache
  [  MEDIUM] [HARDENING] Missing ASLR, CFG, GS Stack Cookie

  [ YARA RULES ]  (6 rules matched)
  [CRITICAL] Ransomware_Indicators
  [CRITICAL] Process_Hollowing
  [    HIGH] Persistence_Scheduled_Task
  [    HIGH] Network_C2_Communication
  [    HIGH] Data_Exfiltration
  [  MEDIUM] Living_off_the_Land

  ══════════════════════════════════════════════════════════
  Threat: 21  |  Risk: CRITICAL  |  Entropy: 1.92
  ══════════════════════════════════════════════════════════
```

Run it yourself: `python demo.py`

---

## Commands

| Command | Description |
|---------|-------------|
| `info` | Full PE analysis — headers, sections, imports, strings, overlays |
| `scan` | Threat-focused scan with risk score and YARA rules |
| `strings` | Extract ASCII/Unicode strings with regex filter |
| `hash` | MD5, SHA1, SHA256, SHA512 |
| `headers` | DOS, COFF, Optional, Rich header dump |
| `sections` | Section table with entropy visualization |
| `imports` | Import and export table listing |
| `compare` | Side-by-side comparison of two PE files |
| `sig` | Digital signature inspection |

### Flags

```bash
--json -o report.json    # Export JSON report
-d /path/to/samples/     # Batch scan directory
--vt                     # VirusTotal lookup (needs VT_API_KEY)
```

---

## Features

**Parsing** — PE32 & PE32+, Rich header, import/export tables, overlay detection

**Heuristics** — Packer detection (UPX, Themida, VMProtect, ASPack, MPRESS...), anti-debug/anti-VM APIs, process injection, privilege escalation, persistence, structural anomalies

**Detection** — 10 built-in YARA rules: ransomware, C2, credential theft, LOLBins, data exfiltration, process hollowing, cryptominers

**Integrations** — VirusTotal hash lookup, JSON export, batch scanning

---

## Architecture

```
winpe_scan/
  pe_parser.py      # Binary parser engine
  heuristics.py     # Threat detection logic
  yara_rules.py     # Built-in detection rules
  virustotal.py     # VT API integration
  display.py        # Terminal output formatting
  models.py         # Data models & constants
  cli.py            # CLI argument parsing
```

---

## Development

```bash
pip install -e ".[dev]"
pytest              # 26 tests
ruff check .        # Lint
mypy winpe_scan/ --ignore-missing-imports  # Types
```

---

## Legal

**For authorized security research and educational purposes only.** Use only on files you own or are authorized to analyze. See [LEGAL.md](LEGAL.md).

---

## License

[MIT](LICENSE)

---

<p align="center">
  Built by <a href="https://github.com/s1d9e">s1d9e</a>
</p>
