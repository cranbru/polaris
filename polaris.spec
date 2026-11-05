# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_all, collect_submodules

datas = [('reports/templates', 'reports/templates')]
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

tmp_ret = collect_all('pyfiglet')
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
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    uac_admin=False,
)
