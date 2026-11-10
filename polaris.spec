# -*- mode: python ; coding: utf-8 -*-
import os
from pathlib import Path
from PIL import Image
from PyInstaller.utils.hooks import collect_all, collect_submodules

spec_root = Path(os.getcwd())
png_path = spec_root / 'Polaris_logo.png'
ico_path = spec_root / 'polaris_logo.ico'

if png_path.exists():
    try:
        img = Image.open(png_path)
        icon_sizes = [(256, 256), (128, 128), (64, 64), (48, 48), (32, 32), (16, 16)]
        img.save(ico_path, format='ICO', sizes=icon_sizes)
    except Exception:
        pass

icon_file = str(ico_path) if ico_path.exists() else None

datas = [('reports/templates', 'reports/templates'), ('desktop/resources', 'desktop/resources')]
binaries = []
hiddenimports = [
    'jinja2',
    'pydantic',
    'typer',
    'rich',
    'LnkParse3',
    'olefile',
    'Evtx',
    'Registry',
]

hiddenimports += collect_submodules('collectors')
hiddenimports += collect_submodules('parsers')
hiddenimports += collect_submodules('analysis')
hiddenimports += collect_submodules('reports')
hiddenimports += collect_submodules('archive')
hiddenimports += collect_submodules('core')
hiddenimports += collect_submodules('config')
hiddenimports += collect_submodules('utils')
hiddenimports += collect_submodules('cli')
hiddenimports += collect_submodules('desktop')
hiddenimports += collect_submodules('ai')

tmp_ret = collect_all('webview')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]
tmp_ret = collect_all('reportlab')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]


a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='polaris',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    uac_admin=False,
    icon=icon_file,
)
