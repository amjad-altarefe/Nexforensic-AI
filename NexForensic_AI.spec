# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['NexForensic_AI_app.py'],
    pathex=[],
    binaries=[],
    datas=[('nexforensic_ai_icon.png', '.'), ('nexforensic_ai_icon.ico', '.')],
    hiddenimports=['lightgbm', 'lightgbm.basic', 'lightgbm.sklearn', 'sklearn', 'joblib', 'numpy', 'pandas', 'shap', 'matplotlib', 'reportlab'],
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
    [],
    exclude_binaries=True,
    name='NexForensic_AI',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['nexforensic_ai_icon.ico'],
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='NexForensic_AI',
)
