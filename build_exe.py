# -*- coding: utf-8 -*-
"""
Protocol Tester Web - 打包脚本
打包成单文件EXE，包含静态资源
"""

import os
import sys
import shutil
import subprocess

# 项目根目录
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
BUILD_DIR = os.path.join(PROJECT_ROOT, 'build')
DIST_DIR = os.path.join(PROJECT_ROOT, 'dist')

def clean_build():
    """清理构建目录"""
    print("[Build] 清理构建目录...")
    for d in [BUILD_DIR, DIST_DIR]:
        if os.path.exists(d):
            shutil.rmtree(d)
            print(f"[Build] 已删除: {d}")

def build_exe():
    """使用PyInstaller打包"""
    print("[Build] 开始打包 protocol-tester-web...")
    
    # 入口脚本 - 创建一个临时入口文件
    entry_script = os.path.join(PROJECT_ROOT, 'run_app.py')
    with open(entry_script, 'w', encoding='utf-8') as f:
        f.write('''# -*- coding: utf-8 -*-
import sys
import os
import socket

# 设置静态文件路径
if getattr(sys, 'frozen', False):
    # 打包后的路径
    base_path = sys._MEIPASS
    os.chdir(base_path)
else:
    base_path = os.path.dirname(os.path.abspath(__file__))

from app import app, socketio, init_app, is_port_available, open_browser

def find_available_port(base_port=5000, max_port=5100):
    """查找可用端口"""
    for port in range(base_port, max_port + 1):
        if is_port_available(port):
            return port
    return None

if __name__ == '__main__':
    init_app()
    
    # 查找可用端口
    port = find_available_port()
    if port is None:
        print("[Protocol Tester] 错误: 端口 5000-5100 均被占用!")
        print("[Protocol Tester] 请关闭其他实例或释放端口后重试")
        input("按回车键退出...")
        sys.exit(1)
    
    print("[Protocol Tester] 启动服务器...")
    print(f"[Protocol Tester] 访问: http://127.0.0.1:{port}")
    
    # 自动打开浏览器
    open_browser(port)
    
    # 启动服务器
    socketio.run(app, host='0.0.0.0', port=port, debug=False)
''')
    
    # 构建参数
    cmd = [
        'pyinstaller',
        '--onefile',              # 单文件
        '--name', 'ProtocolTester',
        '--add-data', f'static{os.pathsep}static',  # 包含静态文件
        '--add-data', f'backend{os.pathsep}backend',  # 包含后端模块
        '--add-data', f'routes{os.pathsep}routes',  # 包含路由
        '--hidden-import', 'flask',
        '--hidden-import', 'flask_socketio',
        '--hidden-import', 'flask_cors',
        '--hidden-import', 'flask_limiter',
        '--hidden-import', 'engineio',
        '--hidden-import', 'engineio.async_drivers.threading',
        '--hidden-import', 'scapy.all',
        '--hidden-import', 'scapy.layers.l2',
        '--hidden-import', 'scapy.layers.inet',
        '--hidden-import', 'psutil',
        '--hidden-import', 'werkzeug',
        '--hidden-import', 'jinja2',
        '--hidden-import', 'markupsafe',
        '--hidden-import', 'itsdangerous',
        '--hidden-import', 'click',
        '--hidden-import', 'blinker',
        '--hidden-import', 'limiter.util',
        '--collect-all', 'flask',
        '--collect-all', 'flask_socketio',
        '--collect-all', 'flask_cors',
        '--collect-all', 'flask_limiter',
        '--collect-all', 'engineio',
        '--collect-all', 'python_engineio',
        '--collect-all', 'python_socketio',
        '--collect-all', 'werkzeug',
        '--noconfirm',            # 不确认覆盖
        '--clean',                # 清理临时文件
        entry_script
    ]
    
    print(f"[Build] 执行: {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=PROJECT_ROOT, capture_output=False, text=True)
    
    # 清理临时入口文件
    if os.path.exists(entry_script):
        os.remove(entry_script)
    
    if result.returncode != 0:
        print(f"[Build] 打包失败! 返回码: {result.returncode}")
        return False
    
    print("[Build] 打包完成!")
    return True

def check_output():
    """检查输出文件"""
    exe_path = os.path.join(DIST_DIR, 'ProtocolTester.exe')
    if os.path.exists(exe_path):
        size = os.path.getsize(exe_path)
        size_mb = size / (1024 * 1024)
        print(f"[Build] 输出文件: {exe_path}")
        print(f"[Build] 文件大小: {size_mb:.2f} MB")
        return exe_path
    else:
        print("[Build] 未找到输出文件!")
        return None

def main():
    print("=" * 60)
    print("Protocol Tester Web - 打包工具")
    print("=" * 60)
    
    clean_build()
    
    if build_exe():
        exe_path = check_output()
        if exe_path:
            print(f"\n[Build] 打包成功!")
            print(f"[Build] EXE路径: {exe_path}")
            print(f"[Build] 使用方法: 双击运行，浏览器访问 http://127.0.0.1:5000")
    else:
        print("\n[Build] 打包失败!")
        sys.exit(1)

if __name__ == '__main__':
    main()
