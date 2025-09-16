# PNmap
Lightweight Python wrapper for safe, authorized security scanning, optimized for USB deployment.
====================================================
 Portable Nmap Scanner (USB Edition)
====================================================

Usage:
  portable_scanner.exe TARGET [options]

Examples:
  portable_scanner.exe 192.168.1.0/24 --yes
  portable_scanner.exe 10.0.0.5 -p 1-1024 --yes

Options:
  -p, --ports     Port range (default: 1-1024)
  --synth         Use SYN scan (-sS). Requires admin + Npcap.
  --out-dir DIR   Save reports into DIR (default: current dir)
  --yes           Skip confirmation prompt
  --verbose       Enable console logging

Reports:
  - Text and JSON reports are written with timestamped filenames.
  - Example: scan_report_20250916T120000Z.txt

Notes:
  - **You need to have nmap.exe and its associated .dlls in the same directory. nmap can be found here: "https://nmap.org/".
  - If you're altering the wrapper, you may need to pull new .dlls using bash (see .spec file).
  - Default scan (-sT) works without admin/Npcap. Recommended for USB use.
  - SYN scan (-sS) may fail if Npcap or admin rights are not present.
  - Reports and logs are saved to the working directory.

Antivirus / SmartScreen:
  - This EXE may trigger Windows Defender SmartScreen or AV warnings.
  - To run: right-click -> "Run anyway" if you trust this file.
  - For professional use, code signing is recommended.

Legal Disclaimer:
  This tool is provided for authorized security testing only.
  Do not scan systems you do not own or have explicit written
  authorization to test. Unauthorized use may be illegal.

====================================================
