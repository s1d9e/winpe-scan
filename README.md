# WinPE-Scan

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/Platform-Windows-0078D4.svg" alt="Platform">
  <img src="https://img.shields.io/badge/Tools-7-blueviolet.svg" alt="Tools">
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/s1d9e/winpe-scan/main/.assets/logo.svg" width="400" alt="WinPE-Scan Logo">
</p>

> *"Knowledge is power, but analysis is understanding..."*

**WinPE-Scan** est un toolkit multi-outils pour l'analyse de fichiers PE Windows (.exe, .dll, .sys). Un outil complet pour l'analyse de malwares et la recherche en sécurité.

---

## ⚠️ Avertissement Légal

> **USAGE ÉDUCATIF UNIQUEMENT**
>
> WinPE-Scan est un outil à **usage éducatif uniquement**. 
> - Utilisez-le uniquement sur des fichiers pour lesquels vous avez l'autorisation
> - L'auteur **ne peut être tenu responsable** de toute utilisation abusive
> - Respectez les lois de votre juridiction

---

## ✨ Fonctionnalités

| Outil | Description |
|-------|-------------|
| 📊 **info** | Analyse complète du fichier PE |
| 🔍 **strings** | Extraction de strings ASCII/Unicode |
| 🔐 **hash** | Calcul de hashes (MD5, SHA1, SHA256, SHA512) |
| 📋 **headers** | Visualisation des headers PE |
| 📦 **sections** | Analyse détaillée des sections |
| 📥 **imports** | Liste des imports/exports |
| ⚖️ **compare** | Comparaison de deux fichiers PE |
| ✓ **sig** | Information sur les signatures |

---

## 📦 Installation

```bash
# Cloner le repo
git clone https://github.com/s1d9e/winpe-scan.git
cd winpe-scan

# Aucune dépendance requise - Python 3.8+ uniquement
python3 winpe-scan.py
```

---

## 🚀 Utilisation

```bash
# Analyse complète
python3 winpe-scan.py info malware.exe

# Extraire les strings
python3 winpe-scan.py strings sample.dll
python3 winpe-scan.py strings file.exe -m 6 -f "http"

# Calculer les hashes
python3 winpe-scan.py hash suspicious.exe

# Voir les headers
python3 winpe-scan.py headers file.exe

# Analyser les sections
python3 winpe-scan.py sections malware.dll

# Lister imports/exports
python3 winpe-scan.py imports sample.exe

# Comparer deux fichiers
python3 winpe-scan.py compare file1.exe file2.exe

# Info signature
python3 winpe-scan.py sig file.exe
```

---

## 🛠️ Outils Détaillés

### info - Analyse Complète
```
python3 winpe-scan.py info malware.exe

[ BASIC INFO ]
  File:     malware.exe
  Size:     45,232 bytes
  MD5:      d41d8cd98f00b204e9800998ecf8427e
  SHA256:   e3b0c44298fc1c149afbf4c8996fb924...

[ SECTIONS ]
  Name       VirtAddr      Entropy
  .text      0x1000        6.87 ⚠️
  .data      0x6000        3.21
```

### strings - Extraction de Strings
```bash
# Strings avec longueur minimale de 6
python3 winpe-scan.py strings malware.exe -m 6

# Filtrer par regex
python3 winpe-scan.py strings file.exe -f "http"
```

### hash - Calcul de Hashes
```
python3 winpe-scan.py hash sample.dll

MD5       d41d8cd98f00b204e9800998ecf8427e
SHA1      da39a3ee5e6b4b0d3255bfef95601890afd80709
SHA256    e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
SHA512    cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce...
```

### compare - Comparaison
```
python3 winpe-scan.py compare file1.exe file2.exe

Hashes:
  File 1: a1b2c3d4...
  File 2: e5f6g7h8...
  Match:  NO

Imports:
  File 1: 12 DLLs
  File 2: 15 DLLs
  Common: kernel32.dll, ntdll.dll, ws2_32.dll
```

---

## 📊 Exemple Complet

```
╔══════════════════════════════════════════════════════════╗
║                   WINPE-SCAN v1.0                      ║
║           Windows PE Multi-Tool Analyzer                ║
╚══════════════════════════════════════════════════════════╝

Tools: info | strings | hash | headers | sections | imports | compare | sig

$ python3 winpe-scan.py info suspicious.exe

[ BASIC INFO ]
──────────────────────────────────────────────────
  File:     suspicious.exe
  Size:     45,232 bytes
  MD5:      d41d8cd98f00b204e9800998ecf8427e
  SHA256:   e3b0c44298fc1c149afbf4c8996fb924...

[ PE HEADERS ]
──────────────────────────────────────────────────
  Machine:      x64
  Sections:      4
  Subsystem:     Windows GUI
  Entry Point:   0x1000

[ SECTIONS ]
──────────────────────────────────────────────────
  Name       VirtAddr      Entropy   Flags
  .text      0x1000        6.87 ⚠️   CODE READ EXEC
  .data      0x6000        3.21      READ WRITE

[ SUSPICIOUS ]
──────────────────────────────────────────────────
  🚨 HIGH   [NETWORK]  http://malicious-domain.com
  🚨 HIGH   [COMMAND]  cmd.exe /c powershell...
```

---

## 🏗️ Structure

```
winpe-scan/
├── winpe-scan.py       # Multi-tool principal
├── README.md
├── LICENSE
├── LEGAL.md
├── .gitignore
└── .assets/
    └── logo.svg
```

---

## 🔧 Technologies

- **Python 3.8+** - 100% Python, zero dépendances
- **Colorama** - Couleurs dans le terminal
- **Struct** - Parsing binaire natif
- **Regex** - Détection de patterns

---

## 🤝 Contribuer

1. Fork le projet
2. Crée une branche (`git checkout -b feature/AmazingFeature`)
3. Commit (`git commit -m 'Add AmazingFeature'`)
4. Push (`git push origin feature/AmazingFeature`)
5. Ouvre une Pull Request

---

## 📜 Licence

MIT License - Voir [LICENSE](LICENSE)

---

<p align="center">
  Made with 🛡️ by <a href="https://github.com/s1d9e">s1d9e</a> | For Educational Purposes Only
</p>
