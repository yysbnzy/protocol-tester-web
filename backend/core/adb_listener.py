# -*- coding: utf-8 -*-
"""ADB 设备连接、无线配对与临时 TCP 监听管理。"""

import ipaddress
import re
import shutil
import subprocess
import time


class ADBListenerManager:
    def __init__(self, adb_port=5555):
        self.adb_port = adb_port
        self.active_serial = None
        self.connection_type = None
        self.target_ip = None
        self.connected_adb_port = None
        self.listener_active = False
        self.listener_port = None
        self._listener_info = None

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

    def _shell(self, adb, serial, command, timeout=6, root=True):
        shell_command = f"su 0 sh -c '{command}'" if root else command
        return self._run([
            adb, '-s', serial, 'shell', shell_command
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

    @staticmethod
    def _split_serial(serial):
        match = re.fullmatch(r'(.+):(\d+)', serial or '')
        if not match:
            return None, None
        try:
            ipaddress.ip_address(match.group(1))
        except ValueError:
            return None, None
        return match.group(1), int(match.group(2))

    def _status(self):
        host, port = self._split_serial(self.active_serial)
        return {
            'connected': bool(self.active_serial),
            'serial': self.active_serial,
            'connection_type': self.connection_type,
            'target_ip': host or self.target_ip,
            'adb_port': port or self.connected_adb_port,
            'listener_active': self.listener_active,
            'listener_port': self.listener_port,
        }

    def list_devices(self, discover=True):
        """读取已连接设备，并通过 mDNS 识别可配对／可连接的无线设备。"""
        adb = shutil.which('adb')
        if not adb:
            return {
                'success': False, 'adb_available': False, 'devices': [],
                'pairable': [], 'connectable': [], 'message': '未检测到 adb',
            }
        try:
            result = self._run([adb, 'devices', '-l'], timeout=6)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {
                'success': False, 'adb_available': True, 'devices': [],
                'pairable': [], 'connectable': [], 'message': str(exc),
            }

        devices = []
        for line in result.stdout.splitlines()[1:]:
            match = re.match(r'^(\S+)\s+(device|offline|unauthorized)\b(.*)$', line.strip())
            if not match:
                continue
            serial, state, detail = match.groups()
            host, _ = self._split_serial(serial)
            devices.append({
                'serial': serial,
                'state': state,
                'connection_type': 'wireless' if host else 'wired',
                'target_ip': host,
                'detail': detail.strip(),
            })

        pairable, connectable = [], []
        if discover:
            try:
                mdns = self._run([adb, 'mdns', 'services'], timeout=5)
                output = f'{mdns.stdout}\n{mdns.stderr}'
                for line in output.splitlines():
                    match = re.search(
                        r'(\S+)\s+(_adb-tls-(pairing|connect)\._tcp\.?)\s+'
                        r'((?:\d{1,3}\.){3}\d{1,3}):(\d+)',
                        line,
                    )
                    if not match:
                        continue
                    name, _, kind, host, port = match.groups()
                    item = {'name': name, 'target_ip': host, 'port': int(port)}
                    (pairable if kind == 'pairing' else connectable).append(item)
            except (OSError, subprocess.TimeoutExpired):
                # mDNS 不可用时仍允许手动输入配对地址。
                pass

        if self.active_serial and not any(
            d['serial'] == self.active_serial and d['state'] == 'device' for d in devices
        ):
            self._clear_connection_state()
        return {
            'success': result.returncode == 0,
            'adb_available': True,
            'devices': devices,
            'pairable': pairable,
            'connectable': connectable,
            'status': self._status(),
        }

    def _set_connection(self, serial, connection_type):
        self.active_serial = serial
        self.connection_type = connection_type
        self.target_ip, self.connected_adb_port = self._split_serial(serial)
        self.listener_active = False
        self.listener_port = None
        self._listener_info = None

    def _clear_connection_state(self):
        self.active_serial = None
        self.connection_type = None
        self.target_ip = None
        self.connected_adb_port = None
        self.listener_active = False
        self.listener_port = None
        self._listener_info = None

    def connect_device(self, method, target_ip, adb_port=5555, serial=None,
                       pair_port=None, pair_code=None, connect_port=None):
        """连接指定设备；无线配对由用户在手机端确认配对码。"""
        events = []
        adb = shutil.which('adb')
        if not adb:
            return self._result(False, ['未检测到 adb'], skipped=True)

        try:
            ipaddress.ip_address(target_ip)
        except ValueError:
            return self._result(False, ['目标 IP 格式无效'])

        if method == 'wired':
            inventory = self.list_devices(discover=False)
            wired = [d for d in inventory['devices']
                     if d['connection_type'] == 'wired' and d['state'] == 'device']
            selected = serial or (wired[0]['serial'] if len(wired) == 1 else None)
            if not selected or not any(d['serial'] == selected for d in wired):
                return self._result(False, ['请选择状态为 device 的有线 ADB 设备'])
            self._set_connection(selected, 'wired')
            events.append(f'有线 ADB 已连接：{selected}')
            return self._result(True, events, serial=selected, status=self._status())

        try:
            adb_port = int(adb_port)
            if not 1 <= adb_port <= 65535:
                raise ValueError
        except (TypeError, ValueError):
            return self._result(False, ['ADB 连接端口必须在 1-65535 之间'])

        if method == 'pair':
            try:
                pair_port = int(pair_port)
                if not 1 <= pair_port <= 65535:
                    raise ValueError
            except (TypeError, ValueError):
                return self._result(False, ['配对端口必须在 1-65535 之间'])
            pair_code = str(pair_code or '').strip()
            if not re.fullmatch(r'\d{6}', pair_code):
                return self._result(False, ['请输入手机显示的六位配对码'])
            pair_serial = f'{target_ip}:{pair_port}'
            try:
                paired = self._run([adb, 'pair', pair_serial, pair_code], timeout=20)
            except (OSError, subprocess.TimeoutExpired) as exc:
                return self._result(False, [f'ADB 配对执行失败：{exc}'])
            output = f'{paired.stdout}\n{paired.stderr}'.strip()
            if paired.returncode != 0 or not re.search(r'successfully paired', output, re.I):
                return self._result(False, [f'ADB 配对失败：{output or "无输出"}'])
            events.append(f'ADB 配对成功：{pair_serial}')

            if not connect_port:
                discovered = self.list_devices(discover=True)
                candidates = [d for d in discovered['connectable'] if d['target_ip'] == target_ip]
                connected = [d for d in discovered['devices']
                             if d['target_ip'] == target_ip and d['state'] == 'device']
                if connected:
                    self._set_connection(connected[0]['serial'], 'wireless_pair')
                    events.append(f'已自动识别并复用无线设备：{connected[0]["serial"]}')
                    return self._result(True, events, serial=self.active_serial, status=self._status())
                if candidates:
                    connect_port = candidates[0]['port']
                    events.append(f'已自动识别无线连接端口：{connect_port}')
            if not connect_port:
                return self._result(False, events + ['配对成功，但未识别到连接端口，请填写无线调试首页显示的端口'])
            adb_port = connect_port
            method_name = 'wireless_pair'
        elif method == 'wireless':
            method_name = 'wireless'
        else:
            return self._result(False, ['不支持的 ADB 连接方式'])

        serial = f'{target_ip}:{adb_port}'
        try:
            connected = self._run([adb, 'connect', serial], timeout=12)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return self._result(False, events + [f'ADB 连接执行失败：{exc}'])
        connect_output = f'{connected.stdout}\n{connected.stderr}'.strip()
        if connected.returncode != 0 or not re.search(r'connected to|already connected', connect_output, re.I):
            return self._result(False, events + [f'ADB 连接未成功：{connect_output or "无输出"}'])
        self._set_connection(serial, method_name)
        events.append(f'ADB 已连接：{serial}')
        return self._result(True, events, serial=serial, status=self._status())

    def ensure_listener(self, target_ip, target_port, serial=None, connection_type=None):
        """已有服务则不改动；无监听时尝试启动 nc 或 python3 临时服务。"""
        events = []
        adb = shutil.which('adb')
        if not adb:
            events.append('未检测到 adb，跳过临时监听准备，继续普通 Socket 握手')
            return self._result(False, events, skipped=True)

        if serial is None:
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
            connection_type = connection_type or 'wireless'
        events.append(f'ADB 已连接：{serial}')

        try:
            root = self._shell(adb, serial, 'id')
        except (OSError, subprocess.TimeoutExpired) as exc:
            events.append(f'ADB root 检查失败：{exc}')
            return self._result(False, events, skipped=False, serial=serial)
        root_output = f'{root.stdout}\n{root.stderr}'.strip()
        use_root = root.returncode == 0 and 'uid=0' in root_output
        if not use_root and target_port < 1024:
            events.append(f'目标机 su 0 不可用，且端口 {target_port} 需要 root：{root_output or "无输出"}')
            self.listener_active = False
            return self._result(False, events, skipped=False, serial=serial, status=self._status())
        events.append('目标机 root 权限检查通过' if use_root else 'root 不可用，高端口尝试普通 shell 监听')

        check_command = self._listen_check_command(target_port)
        listening = self._shell(adb, serial, check_command, root=use_root)
        if listening.returncode == 0:
            events.append(f'目标端口 {target_port} 已有 TCP 监听，不启动临时服务')
            result = self._result(True, events, skipped=False, serial=serial)
            self._set_connection(serial, connection_type or self.connection_type or 'wireless')
            self.listener_active = True
            self.listener_port = target_port
            self._listener_info = result
            result['status'] = self._status()
            return result

        log_path = f'/tmp/protocol-tester-{target_port}.log'
        start_command = (
            "if command -v nc >/dev/null 2>&1; then "
            f"nohup nc -l -p {target_port} >{log_path} 2>&1 </dev/null & echo $!; "
            "elif command -v python3 >/dev/null 2>&1; then "
            f"nohup python3 -m http.server {target_port} --bind 0.0.0.0 >{log_path} 2>&1 </dev/null & echo $!; "
            "else exit 127; fi"
        )
        started = self._shell(adb, serial, start_command, root=use_root)
        pid_match = re.search(r'(?m)^\s*(\d+)\s*$', started.stdout)
        if started.returncode != 0 or not pid_match:
            output = f'{started.stdout}\n{started.stderr}'.strip()
            events.append(f'临时监听启动失败：{output or "目标机缺少 nc/python3"}')
            self.listener_active = False
            return self._result(False, events, skipped=False, serial=serial, status=self._status())

        listener_pid = int(pid_match.group(1))
        time.sleep(0.5)
        confirmed = self._shell(adb, serial, check_command, root=use_root)
        if confirmed.returncode != 0:
            self._shell(adb, serial, f'kill {listener_pid} 2>/dev/null || true', root=use_root)
            events.append(f'临时进程 {listener_pid} 已启动，但端口 {target_port} 未进入 LISTEN')
            self.listener_active = False
            return self._result(False, events, skipped=False, serial=serial, status=self._status())

        events.append(f'临时 TCP 监听已就绪：{target_ip}:{target_port}，PID={listener_pid}')
        result = self._result(
            True,
            events,
            created=True,
            listener_pid=listener_pid,
            serial=serial,
            use_root=use_root,
        )
        self._set_connection(serial, connection_type or self.connection_type or 'wireless')
        self.listener_active = True
        self.listener_port = target_port
        self._listener_info = result
        result['status'] = self._status()
        return result

    def prepare_for_handshake(self, target_ip, target_port):
        """一键握手只复用面板中已连接的 ADB 设备，不再固定连接 5555。"""
        if not self.active_serial:
            return None
        if self.target_ip and self.target_ip != target_ip:
            return self._result(False, [
                f'ADB 设备地址 {self.target_ip} 与 Socket 目标 {target_ip} 不一致，请重新选择连接'
            ], serial=self.active_serial, status=self._status())
        return self.ensure_listener(
            target_ip, target_port,
            serial=self.active_serial,
            connection_type=self.connection_type,
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
            result = self._shell(
                adb, serial, f'kill {pid} 2>/dev/null || true',
                root=listener_info.get('use_root', True),
            )
            cleaned = result.returncode == 0
            if cleaned and self.listener_port is not None:
                self.listener_active = False
                self.listener_port = None
                self._listener_info = None
            return cleaned
        except (OSError, subprocess.TimeoutExpired):
            return False


adb_listener = ADBListenerManager()
