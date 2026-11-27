# -*- coding: utf-8 -*-
"""Socket 握手前，通过 ADB 在测试设备上准备临时 TCP 监听。"""

import re
import shutil
import subprocess
import time


class ADBListenerManager:
    def __init__(self, adb_port=5555):
        self.adb_port = adb_port

    def _run(self, args, timeout=6):
        kwargs = {
            'capture_output': True,
            'text': True,
            'encoding': 'utf-8',
            'errors': 'replace',
            'timeout': timeout,
        }
        if hasattr(subprocess, 'CREATE_NO_WINDOW'):
            kwargs['creationflags'] = subprocess.CREATE_NO_WINDOW
        return subprocess.run(args, **kwargs)

    @staticmethod
    def _result(success, events, **extra):
        result = {
            'success': success,
            'created': False,
            'listener_pid': None,
            'events': events,
        }
        result.update(extra)
        return result

    def _shell(self, adb, serial, command, timeout=6):
        return self._run([
            adb, '-s', serial, 'shell', f"su 0 sh -c '{command}'"
        ], timeout=timeout)

    @staticmethod
    def _listen_check_command(port):
        # ss/netstat 的地址列兼容 0.0.0.0:80、:::80 等格式。
        expression = f'[:.]{port}'
        return (
            "if command -v ss >/dev/null 2>&1; then "
            f"ss -tln | grep -Eq '{expression}[[:space:]]'; "
            "elif command -v netstat >/dev/null 2>&1; then "
            f"netstat -lnt | grep -Eq '{expression}[[:space:]]'; "
            "else exit 127; fi"
        )

    def ensure_listener(self, target_ip, target_port):
        """已有服务则不改动；无监听时尝试启动 nc 或 python3 临时服务。"""
        events = []
        adb = shutil.which('adb')
        if not adb:
            events.append('未检测到 adb，跳过临时监听准备，继续普通 Socket 握手')
            return self._result(False, events, skipped=True)

        serial = f'{target_ip}:{self.adb_port}'
        try:
            connected = self._run([adb, 'connect', serial], timeout=8)
        except (OSError, subprocess.TimeoutExpired) as exc:
            events.append(f'ADB 连接执行失败：{exc}，继续普通 Socket 握手')
            return self._result(False, events, skipped=True)
        connect_output = f'{connected.stdout}\n{connected.stderr}'.strip()
        if connected.returncode != 0 or not re.search(r'connected to|already connected', connect_output, re.I):
            events.append(f'ADB 连接未成功：{connect_output or "无输出"}，继续普通 Socket 握手')
            return self._result(False, events, skipped=True)
        events.append(f'ADB 已连接：{serial}')

        try:
            root = self._shell(adb, serial, 'id')
        except (OSError, subprocess.TimeoutExpired) as exc:
            events.append(f'ADB root 检查失败：{exc}，继续普通 Socket 握手')
            return self._result(False, events, skipped=True)
        root_output = f'{root.stdout}\n{root.stderr}'.strip()
        if root.returncode != 0 or 'uid=0' not in root_output:
            events.append(f'目标机 su 0 不可用：{root_output or "无输出"}，继续普通 Socket 握手')
            return self._result(False, events, skipped=True)
        events.append('目标机 root 权限检查通过')

        check_command = self._listen_check_command(target_port)
        listening = self._shell(adb, serial, check_command)
        if listening.returncode == 0:
            events.append(f'目标端口 {target_port} 已有 TCP 监听，不启动临时服务')
            return self._result(True, events, skipped=False)

        log_path = f'/tmp/protocol-tester-{target_port}.log'
        start_command = (
            "if command -v nc >/dev/null 2>&1; then "
            f"nohup nc -l -p {target_port} >{log_path} 2>&1 </dev/null & echo $!; "
            "elif command -v python3 >/dev/null 2>&1; then "
            f"nohup python3 -m http.server {target_port} --bind 0.0.0.0 >{log_path} 2>&1 </dev/null & echo $!; "
            "else exit 127; fi"
        )
        started = self._shell(adb, serial, start_command)
        pid_match = re.search(r'(?m)^\s*(\d+)\s*$', started.stdout)
        if started.returncode != 0 or not pid_match:
            output = f'{started.stdout}\n{started.stderr}'.strip()
            events.append(f'临时监听启动失败：{output or "目标机缺少 nc/python3"}')
            return self._result(False, events, skipped=False)

        listener_pid = int(pid_match.group(1))
        time.sleep(0.5)
        confirmed = self._shell(adb, serial, check_command)
        if confirmed.returncode != 0:
            self._shell(adb, serial, f'kill {listener_pid} 2>/dev/null || true')
            events.append(f'临时进程 {listener_pid} 已启动，但端口 {target_port} 未进入 LISTEN')
            return self._result(False, events, skipped=False)

        events.append(f'临时 TCP 监听已就绪：{target_ip}:{target_port}，PID={listener_pid}')
        return self._result(
            True,
            events,
            created=True,
            listener_pid=listener_pid,
            serial=serial,
        )

    def cleanup_listener(self, listener_info):
        """仅清理由本工具创建的临时监听，不动目标原有服务。"""
        if not listener_info or not listener_info.get('created'):
            return False
        adb = shutil.which('adb')
        if not adb:
            return False
        serial = listener_info.get('serial')
        pid = listener_info.get('listener_pid')
        if not serial or not pid:
            return False
        try:
            result = self._shell(adb, serial, f'kill {pid} 2>/dev/null || true')
            return result.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            return False


adb_listener = ADBListenerManager()
