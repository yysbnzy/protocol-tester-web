# -*- coding: utf-8 -*-
"""
UI 测试执行脚本 - 在服务器已启动的情况下运行
"""

import subprocess
import sys

def run_tests():
    """运行 UI 测试"""
    # 先测试页面加载
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/ui/test_page_load.py", "-v", "--tb=short"],
        capture_output=True,
        text=True
    )
    print("=== test_page_load.py ===")
    print(result.stdout)
    if result.stderr:
        print("STDERR:", result.stderr)
    
    # 测试协议切换
    result2 = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/ui/test_protocol.py", "-v", "--tb=short"],
        capture_output=True,
        text=True
    )
    print("\n=== test_protocol.py ===")
    print(result2.stdout)
    if result2.stderr:
        print("STDERR:", result2.stderr)
    
    return result.returncode, result2.returncode

if __name__ == "__main__":
    run_tests()
