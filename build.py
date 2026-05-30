# -*- coding: utf-8 -*-
"""
PyInstaller 打包脚本
打包协议字段测试工具为 Windows EXE
"""

import os
import sys
import shutil

# 确保在正确目录
base_dir = os.path.dirname(os.path.abspath(__file__))
os.chdir(base_dir)

# 检查 PyInstaller
spec_content = '''
# -*- mode: python ; coding: utf-8 -*-

import sys
import os

block_cipher = None

a = Analysis(
    ['app.py'],
    pathex=[r'%s'],
    binaries=[],
    datas=[
        ('static', 'static'),
        ('config', 'config'),
    ],
    hiddenimports=[
        'scapy.all',
        'scapy.layers.l2',
        'scapy.layers.inet',
        'scapy.packet',
        'flask',
        'flask_socketio',
        'flask_cors',
        'psutil',
        'engineio',
        'engineio.async_drivers.threading',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='ProtocolTester',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='static/favicon.ico' if os.path.exists('static/favicon.ico') else None,
)
''' % base_dir

# 写入 spec 文件
with open('ProtocolTester.spec', 'w', encoding='utf-8') as f:
    f.write(spec_content)

print('='*50)
print('协议字段测试工具 - PyInstaller 打包脚本')
print('='*50)
print()
print('打包步骤:')
print('1. 安装依赖:  pip install -r requirements.txt')
print('2. 打包命令:  pyinstaller ProtocolTester.spec')
print()
print('输出位置: dist/ProtocolTester.exe')
print('='*50)
