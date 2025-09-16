# portable_scanner.spec
# PyInstaller spec file for USB-optimized Nmap scanner (for those who want to compile their own)
# Build with: pyinstaller portable_scanner.spec

block_cipher = None

a = Analysis(
    ['port_scanner.py'],
    pathex=[],
    binaries=[
        ('nmap_bin/nmap.exe', '.'),
        ('nmap_bin/*.dll', '.'),
    ],
    datas=[
        ('README.txt', '.'),
    ],
    hiddenimports=['nmap'],
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='portable_scanner',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='portable_scanner'
)
