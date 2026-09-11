# -*- coding: utf-8 -*-
"""
协议报文组装器
组装各种协议的报文，支持合法值和非法值
"""

import struct
import re


class PacketAssembler:
    """报文组装器"""
    
    def __init__(self):
        self.protocol_builders = {
            'ARP': self._build_arp,
            'IP': self._build_ip,
            'TCP': self._build_tcp,
            'UDP': self._build_udp,
            'ICMP': self._build_icmp,
            'SOMEIP': self._build_someip,
            'SOMEIP-SD': self._build_someip_sd,
            'DOIP': self._build_doip
        }
        
        # 协议字段验证规则
        self.validation_rules = {
            'port': {
                'min': 0,
                'max': 65535,
                'error_msg': '端口号必须在 0-65535 之间'
            },
            'u8': {  # 8位无符号整数
                'min': 0,
                'max': 255,
                'error_msg': '值必须在 0-255 之间'
            },
            'u16': {  # 16位无符号整数
                'min': 0,
                'max': 65535,
                'error_msg': '值必须在 0-65535 之间'
            },
            'u32': {  # 32位无符号整数
                'min': 0,
                'max': 4294967295,
                'error_msg': '值必须在 0-4294967295 之间'
            }
        }
    
    def _validate_port(self, value, field_name='端口号'):
        """验证端口号"""
        try:
            port = self._parse_value(value, 0)
            if port < 0 or port > 65535:
                return False, f'{field_name}必须在 0-65535 之间，当前值: {port}'
            return True, port
        except (ValueError, TypeError):
            return False, f'{field_name}必须是有效的数字，当前值: {value}'
    
    def _validate_ip(self, ip_str, field_name='IP地址'):
        """验证IP地址格式"""
        if not ip_str or not isinstance(ip_str, str):
            return False, f'{field_name}不能为空'
        
        # 基本IP格式验证
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if not re.match(ip_pattern, ip_str):
            return False, f'{field_name}格式错误，应为 xxx.xxx.xxx.xxx 格式，当前值: {ip_str}'
        
        # 验证每个段的范围
        parts = ip_str.split('.')
        for i, part in enumerate(parts):
            try:
                num = int(part)
                if num < 0 or num > 255:
                    return False, f'{field_name}第{i+1}段必须在 0-255 之间，当前值: {part}'
            except (ValueError, TypeError):
                return False, f'{field_name}包含无效数字: {part}'
        
        return True, ip_str
    
    def _validate_u8(self, value, field_name='值'):
        """验证8位无符号整数"""
        try:
            num = self._parse_value(value, 0)
            if num < 0 or num > 255:
                return False, f'{field_name}必须在 0-255 之间，当前值: {num}'
            return True, num
        except (ValueError, TypeError):
            return False, f'{field_name}必须是有效的数字，当前值: {value}'
    
    def _validate_u16(self, value, field_name='值'):
        """验证16位无符号整数"""
        try:
            num = self._parse_value(value, 0)
            if num < 0 or num > 65535:
                return False, f'{field_name}必须在 0-65535 之间，当前值: {num}'
            return True, num
        except (ValueError, TypeError):
            return False, f'{field_name}必须是有效的数字，当前值: {value}'
    
    def _validate_u32(self, value, field_name='值'):
        """验证32位无符号整数"""
        try:
            num = self._parse_value(value, 0)
            if num < 0 or num > 4294967295:
                return False, f'{field_name}必须在 0-4294967295 之间，当前值: {num}'
            return True, num
        except (ValueError, TypeError):
            return False, f'{field_name}必须是有效的数字，当前值: {value}'
    
    def _validate_mac(self, mac_str, field_name='MAC地址'):
        """验证MAC地址格式"""
        if not mac_str or not isinstance(mac_str, str):
            return False, f'{field_name}不能为空'
        
        # 支持格式: 00:11:22:33:44:55 或 00-11-22-33-44-55 或 001122334455
        mac_clean = mac_str.replace(':', '').replace('-', '').upper()
        
        if len(mac_clean) != 12:
            return False, f'{field_name}格式错误，应为6字节(12个十六进制字符)，当前: {mac_str}'
        
        if not all(c in '0123456789ABCDEF' for c in mac_clean):
            return False, f'{field_name}包含非法字符，应为十六进制字符，当前: {mac_str}'
        
        return True, mac_str
    
    def assemble(self, protocol, fields, illegal_fields=None, illegal_values=None):
        """
        组装报文
        
        Args:
            protocol: 协议类型
            fields: 字段值字典 {field_name: value}
            illegal_fields: 非法字段列表
            illegal_values: 非法字段值字典 {field_name: value}
            
        Returns:
            dict: {success, packet_hex, packet_bytes, layers, error}
        """
        illegal_fields = illegal_fields or []
        illegal_values = illegal_values or {}
        builder = self.protocol_builders.get(protocol)
        
        if not builder:
            return {
                'success': False,
                'error': f'不支持的协议: {protocol}',
                'packet_hex': '',
                'packet_bytes': [],
                'layers': []
            }
        
        # 用 illegal_values 替换 fields 中对应字段的值
        # 注意：这里不校验非法值的范围
        merged_fields = dict(fields)  # 复制一份
        for field_name in illegal_fields:
            if field_name in illegal_values:
                merged_fields[field_name] = illegal_values[field_name]
        
        # 字段名去前缀：支持 TCP.srcport -> srcport 的兼容
        prefix_map = {
            'TCP': 'TCP.',
            'UDP': 'UDP.',
            'IP': 'IP.',
            'ICMP': 'ICMP.',
            'ARP': 'ARP.',
            'SOMEIP': 'SOMEIP.',
            'SOMEIP-SD': 'SOMEIP-SD.',
            'DOIP': 'DOIP.'
        }
        prefix = prefix_map.get(protocol, '')
        if prefix:
            clean_fields = {}
            for k, v in merged_fields.items():
                if k.startswith(prefix):
                    clean_fields[k[len(prefix):]] = v
                else:
                    clean_fields[k] = v
            merged_fields = clean_fields
            # 同步去前缀 illegal_fields
            illegal_fields = [f[len(prefix):] if f.startswith(prefix) else f for f in illegal_fields]
        
        # 先进行输入验证（只验证非非法字段）
        validation_result = self._validate_inputs(protocol, merged_fields, illegal_fields)
        if not validation_result['valid']:
            return {
                'success': False,
                'error': validation_result['error'],
                'packet_hex': '',
                'packet_bytes': [],
                'layers': []
            }
        
        try:
            result = builder(merged_fields, illegal_fields)
            # 将 bytes 转换为 list 以便 JSON 序列化
            if 'packet_bytes' in result and isinstance(result['packet_bytes'], bytes):
                result['packet_bytes'] = list(result['packet_bytes'])
            return result
        except struct.error as e:
            # 捕获 struct 错误并转换为友好提示
            error_msg = str(e)
            if 'requires 0 <= number' in error_msg:
                return {
                    'success': False,
                    'error': '数值超出有效范围，请检查输入值是否在允许范围内',
                    'packet_hex': '',
                    'packet_bytes': [],
                    'layers': []
                }
            return {
                'success': False,
                'error': f'数据格式错误: {error_msg}',
                'packet_hex': '',
                'packet_bytes': [],
                'layers': []
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'组装失败: {str(e)}',
                'packet_hex': '',
                'packet_bytes': [],
                'layers': []
            }
    
    def _validate_inputs(self, protocol, fields, illegal_fields=None):
        """
        根据协议类型验证输入
        
        Args:
            protocol: 协议类型
            fields: 字段值
            illegal_fields: 非法字段列表（这些字段跳过验证）n        
        Returns:
            dict: {'valid': bool, 'error': str}
        """
        illegal_fields = illegal_fields or []
        
        try:
            if protocol == 'TCP':
                return self._validate_tcp_inputs(fields, illegal_fields)
            elif protocol == 'IP':
                return self._validate_ip_inputs(fields, illegal_fields)
            elif protocol == 'UDP':
                return self._validate_udp_inputs(fields, illegal_fields)
            elif protocol == 'ICMP':
                return self._validate_icmp_inputs(fields, illegal_fields)
            elif protocol == 'ARP':
                return self._validate_arp_inputs(fields, illegal_fields)
            elif protocol in ['SOMEIP', 'SOMEIP-SD']:
                return self._validate_someip_inputs(fields, illegal_fields)
            else:
                # 其他协议暂不详细验证
                return {'valid': True, 'error': None}
        except Exception as e:
            return {'valid': False, 'error': f'输入验证失败: {str(e)}'}
    
    def _validate_tcp_inputs(self, fields, illegal_fields=None):
        """验证TCP输入（跳过非法字段）"""
        illegal_fields = illegal_fields or []
        
        # 验证源端口（如果不是非法字段）
        if 'srcport' in fields and 'srcport' not in illegal_fields:
            valid, result = self._validate_port(fields['srcport'], '源端口')
            if not valid:
                return {'valid': False, 'error': result}
        
        # 验证目的端口（如果不是非法字段）
        if 'dstport' in fields and 'dstport' not in illegal_fields:
            valid, result = self._validate_port(fields['dstport'], '目的端口')
            if not valid:
                return {'valid': False, 'error': result}
        
        # 验证seq号（如果不是非法字段）
        if 'seq' in fields and 'seq' not in illegal_fields:
            valid, result = self._validate_u32(fields['seq'], '序列号(seq)')
            if not valid:
                return {'valid': False, 'error': result}
        
        # 验证ack号（如果不是非法字段）
        if 'ack' in fields and 'ack' not in illegal_fields:
            valid, result = self._validate_u32(fields['ack'], '确认号(ack)')
            if not valid:
                return {'valid': False, 'error': result}
        
        # 验证窗口大小（如果不是非法字段）
        if 'window_size' in fields and 'window_size' not in illegal_fields:
            valid, result = self._validate_u16(fields['window_size'], '窗口大小')
            if not valid:
                return {'valid': False, 'error': result}
        
        return {'valid': True, 'error': None}
    
    def _validate_ip_inputs(self, fields, illegal_fields=None):
        """验证IP输入（跳过非法字段）"""
        illegal_fields = illegal_fields or []
        
        # 验证版本（如果不是非法字段）
        if 'version' in fields and 'version' not in illegal_fields:
            valid, result = self._validate_u8(fields['version'], 'IP版本')
            if not valid:
                return {'valid': False, 'error': result}
            # IP版本通常是4或6
            if result not in [4, 6]:
                return {'valid': False, 'error': f'IP版本必须是4或6，当前值: {result}'}
        
        # 验证TTL（如果不是非法字段）
        if 'ttl' in fields and 'ttl' not in illegal_fields:
            valid, result = self._validate_u8(fields['ttl'], 'TTL')
            if not valid:
                return {'valid': False, 'error': result}
        
        # 验证源IP（如果不是非法字段）
        if 'src' in fields and 'src' not in illegal_fields:
            valid, result = self._validate_ip(fields['src'], '源IP地址')
            if not valid:
                return {'valid': False, 'error': result}
        
        # 验证目的IP（如果不是非法字段）
        if 'dst' in fields and 'dst' not in illegal_fields:
            valid, result = self._validate_ip(fields['dst'], '目的IP地址')
            if not valid:
                return {'valid': False, 'error': result}
        
        # 验证TOS（如果不是非法字段）
        if 'tos' in fields and 'tos' not in illegal_fields:
            valid, result = self._validate_u8(fields['tos'], 'TOS')
            if not valid:
                return {'valid': False, 'error': result}
        
        # 验证ID（如果不是非法字段）
        if 'id' in fields and 'id' not in illegal_fields:
            valid, result = self._validate_u16(fields['id'], '标识符(ID)')
            if not valid:
                return {'valid': False, 'error': result}
        
        return {'valid': True, 'error': None}
    
    def _validate_udp_inputs(self, fields, illegal_fields=None):
        """验证UDP输入（跳过非法字段）"""
        illegal_fields = illegal_fields or []
        
        if 'srcport' in fields and 'srcport' not in illegal_fields:
            valid, result = self._validate_port(fields['srcport'], '源端口')
            if not valid:
                return {'valid': False, 'error': result}
        
        if 'dstport' in fields and 'dstport' not in illegal_fields:
            valid, result = self._validate_port(fields['dstport'], '目的端口')
            if not valid:
                return {'valid': False, 'error': result}
        
        if 'length' in fields and 'length' not in illegal_fields:
            valid, result = self._validate_u16(fields['length'], '长度')
            if not valid:
                return {'valid': False, 'error': result}
        
        if 'checksum' in fields and 'checksum' not in illegal_fields:
            valid, result = self._validate_u16(fields['checksum'], '校验和')
            if not valid:
                return {'valid': False, 'error': result}
        
        return {'valid': True, 'error': None}
    
    def _validate_icmp_inputs(self, fields, illegal_fields=None):
        """验证ICMP输入（跳过非法字段）"""
        illegal_fields = illegal_fields or []
        
        if 'type' in fields and 'type' not in illegal_fields:
            valid, result = self._validate_u8(fields['type'], '类型(type)')
            if not valid:
                return {'valid': False, 'error': result}
        
        if 'code' in fields and 'code' not in illegal_fields:
            valid, result = self._validate_u8(fields['code'], '代码(code)')
            if not valid:
                return {'valid': False, 'error': result}
        
        if 'id' in fields and 'id' not in illegal_fields:
            valid, result = self._validate_u16(fields['id'], '标识符(id)')
            if not valid:
                return {'valid': False, 'error': result}
        
        if 'seq' in fields and 'seq' not in illegal_fields:
            valid, result = self._validate_u16(fields['seq'], '序列号(seq)')
            if not valid:
                return {'valid': False, 'error': result}
        
        return {'valid': True, 'error': None}
    
    def _validate_arp_inputs(self, fields, illegal_fields=None):
        """验证ARP输入（跳过非法字段）"""
        illegal_fields = illegal_fields or []
        
        if 'src.hw_mac' in fields and 'src.hw_mac' not in illegal_fields:
            valid, result = self._validate_mac(fields['src.hw_mac'], '源MAC地址')
            if not valid:
                return {'valid': False, 'error': result}
        
        if 'dst.hw_mac' in fields and 'dst.hw_mac' not in illegal_fields:
            valid, result = self._validate_mac(fields['dst.hw_mac'], '目的MAC地址')
            if not valid:
                return {'valid': False, 'error': result}
        
        return {'valid': True, 'error': None}
    
    def _validate_someip_inputs(self, fields, illegal_fields=None):
        """验证SOME/IP输入（跳过非法字段）"""
        illegal_fields = illegal_fields or []
        
        # 验证 service ID（如果不是非法字段）
        if 'service' in fields and 'service' not in illegal_fields:
            valid, result = self._validate_u16(fields['service'], 'Service ID')
            if not valid:
                return {'valid': False, 'error': result}
        
        # 验证 method ID（如果不是非法字段）
        if 'method' in fields and 'method' not in illegal_fields:
            valid, result = self._validate_u16(fields['method'], 'Method ID')
            if not valid:
                return {'valid': False, 'error': result}
        
        # 验证 client ID（如果不是非法字段）
        if 'client' in fields and 'client' not in illegal_fields:
            valid, result = self._validate_u16(fields['client'], 'Client ID')
            if not valid:
                return {'valid': False, 'error': result}
        
        # 验证 session ID（如果不是非法字段）
        if 'session' in fields and 'session' not in illegal_fields:
            valid, result = self._validate_u16(fields['session'], 'Session ID')
            if not valid:
                return {'valid': False, 'error': result}
        
        # 验证 protocol version（如果不是非法字段）
        if 'proto_ver' in fields and 'proto_ver' not in illegal_fields:
            valid, result = self._validate_u8(fields['proto_ver'], 'Protocol Version')
            if not valid:
                return {'valid': False, 'error': result}
        
        # 验证 interface version（如果不是非法字段）
        if 'iface_ver' in fields and 'iface_ver' not in illegal_fields:
            valid, result = self._validate_u8(fields['iface_ver'], 'Interface Version')
            if not valid:
                return {'valid': False, 'error': result}
        
        return {'valid': True, 'error': None}
    
    def _parse_value(self, value_str, default=0):
        """解析字段值"""
        if value_str is None or value_str == '':
            return default
        
        value_str = str(value_str).strip()
        
        if not value_str:
            return default
        
        # 十六进制
        if value_str.startswith('0x') or value_str.startswith('0X'):
            try:
                return int(value_str, 16)
            except ValueError:
                return default
        
        # 十进制
        try:
            return int(value_str)
        except ValueError:
            return default
    
    def _parse_ip(self, ip_str):
        """解析 IP 地址为字节"""
        try:
            parts = ip_str.split('.')
            return bytes([int(p) for p in parts])
        except (ValueError, IndexError):
            return bytes([192, 168, 1, 1])  # 默认
    
    def _mac_to_bytes(self, mac_str, field_name='MAC地址'):
        """
        将 MAC 地址转换为 6 字节，容忍非法输入。
        非法字段测试时用户可能填入 'GG:GG:...' 等无法解析的值，
        此时提取其中的十六进制字符，不足 12 位用 'F' 补齐，保证组装不中断。
        """
        cleaned = (mac_str or '').replace(':', '').replace('-', '').upper()
        hex_only = ''.join(c for c in cleaned if c in '0123456789ABCDEF')
        hex_only = (hex_only + 'F' * 12)[:12]
        try:
            return bytes.fromhex(hex_only)
        except ValueError:
            return b'\xff' * 6

    def _build_arp(self, fields, illegal_fields):
        """构建 ARP 报文（完整28字节）"""
        layers = []
        
        # ARP 字段
        proto_type = self._parse_value(fields.get('proto.type') or '0x0800')
        opcode = self._parse_value(fields.get('opcode') or '1')
        src_mac = fields.get('src.hw_mac') or '00:11:22:33:44:55'
        dst_mac = fields.get('dst.hw_mac') or '00:00:00:00:00:00'
        src_ip = fields.get('src_ip') or '192.168.1.100'
        dst_ip = fields.get('dst_ip') or '192.168.1.1'
        
        arp_fields = [
            {'name': 'Hardware Type', 'value': '0x0001 (Ethernet)', 'illegal': False},
            {'name': 'Protocol Type', 'value': f'0x{proto_type:04X}', 'illegal': 'proto.type' in illegal_fields},
            {'name': 'Hardware Size', 'value': '6', 'illegal': False},
            {'name': 'Protocol Size', 'value': '4', 'illegal': False},
            {'name': 'Opcode', 'value': f'0x{opcode:04X}', 'illegal': 'opcode' in illegal_fields},
            {'name': 'Sender MAC', 'value': src_mac, 'illegal': 'src.hw_mac' in illegal_fields},
            {'name': 'Sender IP', 'value': src_ip, 'illegal': 'src_ip' in illegal_fields},
            {'name': 'Target MAC', 'value': dst_mac, 'illegal': 'dst.hw_mac' in illegal_fields},
            {'name': 'Target IP', 'value': dst_ip, 'illegal': 'dst_ip' in illegal_fields},
        ]
        layers.append({'name': 'ARP', 'fields': arp_fields})
        
        # 构建字节：header(8) + sender_mac(6) + sender_ip(4) + target_mac(6) + target_ip(4) = 28字节
        src_mac_bytes = self._mac_to_bytes(src_mac, 'Sender MAC')
        dst_mac_bytes = self._mac_to_bytes(dst_mac, 'Target MAC')
        src_ip_bytes = self._parse_ip(src_ip)
        dst_ip_bytes = self._parse_ip(dst_ip)
        
        packet_bytes = struct.pack('>HHBBH', 0x0001, proto_type, 6, 4, opcode)
        packet_bytes += src_mac_bytes + src_ip_bytes + dst_mac_bytes + dst_ip_bytes
        
        return {
            'success': True,
            'packet_hex': packet_bytes.hex(),
            'packet_bytes': packet_bytes,
            'layers': layers,
            'error': None
        }
    
    def _build_ip(self, fields, illegal_fields):
        """构建 IP 报文"""
        layers = []
        
        # IP 字段
        version = self._parse_value(fields.get('version') or '4')
        tos = self._parse_value(fields.get('tos') or '0')
        ident = self._parse_value(fields.get('id') or '0x1234')
        ttl = self._parse_value(fields.get('ttl') or '64')
        checksum = self._parse_value(fields.get('checksum') or '0')
        src_ip = self._parse_ip(fields.get('src') or '192.168.1.100')
        dst_ip = self._parse_ip(fields.get('dst') or '192.168.1.1')
        
        # 协议号：从字段获取，或由调用方通过 _ip_protocol 传入
        protocol_num = self._parse_value(fields.get('_ip_protocol') or '6')
        proto_name_map = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}
        proto_display = f'{proto_name_map.get(protocol_num, f"Unknown")} ({protocol_num})'
        
        # IP报文长度：header(20) + 上层payload长度（如有）
        ip_total_len = 20 + self._parse_value(fields.get('_payload_len') or '0')
        
        ip_fields = [
            {'name': 'Version', 'value': str(version), 'illegal': 'version' in illegal_fields},
            {'name': 'IHL', 'value': '5', 'illegal': False},
            {'name': 'TOS', 'value': f'0x{tos:02X}', 'illegal': 'tos' in illegal_fields},
            {'name': 'Total Length', 'value': str(ip_total_len), 'illegal': False},
            {'name': 'Identification', 'value': f'0x{ident:04X}', 'illegal': 'id' in illegal_fields},
            {'name': 'Flags', 'value': '0x0000', 'illegal': False},
            {'name': 'TTL', 'value': str(ttl), 'illegal': 'ttl' in illegal_fields},
            {'name': 'Protocol', 'value': proto_display, 'illegal': False},
            {'name': 'Checksum', 'value': f'0x{checksum:04X}', 'illegal': 'checksum' in illegal_fields},
            {'name': 'Source IP', 'value': fields.get('src', '192.168.1.100'), 'illegal': 'src' in illegal_fields},
            {'name': 'Dest IP', 'value': fields.get('dst', '192.168.1.1'), 'illegal': 'dst' in illegal_fields},
        ]
        layers.append({'name': 'IP', 'fields': ip_fields})
        
        # 构建字节
        packet_bytes = struct.pack('>BBHHHBBH',
            (version << 4) | 5,  # Version + IHL
            tos,
            ip_total_len,  # Total length
            ident,
            0x0000,  # Flags + Fragment offset
            ttl,
            protocol_num,  # Protocol (动态)
            checksum
        ) + src_ip + dst_ip
        
        return {
            'success': True,
            'packet_hex': packet_bytes.hex(),
            'packet_bytes': packet_bytes,
            'layers': layers,
            'error': None
        }
    
    def _build_tcp(self, fields, illegal_fields):
        """构建 TCP 报文"""
        layers = []
        
        # TCP 字段
        src_port = self._parse_value(fields.get('srcport') or '12345')
        dst_port = self._parse_value(fields.get('dstport') or '80')
        seq = self._parse_value(fields.get('seq') or '0')
        ack = self._parse_value(fields.get('ack') or '0')
        flags = self._parse_value(fields.get('flags') or '0x02')
        window = self._parse_value(fields.get('window_size') or '65535')
        checksum = self._parse_value(fields.get('checksum') or '0')
        options = fields.get('options', '')  # TCP Options 字段
        
        # 对于非法字段，截断值以适应 struct 格式（模拟溢出行为）
        if 'srcport' in illegal_fields:
            src_port = src_port & 0xFFFF  # 截断到 16 位
        if 'dstport' in illegal_fields:
            dst_port = dst_port & 0xFFFF
        if 'window_size' in illegal_fields:
            window = window & 0xFFFF
        
        # 解析 Options 字节
        options_bytes = b''
        if options:
            try:
                # 支持 0x 开头的十六进制字符串
                options_str = options.strip()
                if options_str.startswith('0x'):
                    options_str = options_str[2:]
                # 移除空格
                options_str = options_str.replace(' ', '')
                if options_str:
                    options_bytes = bytes.fromhex(options_str)
            except ValueError:
                options_bytes = b''
        
        # 计算 Data Offset (以 4 字节为单位，最小是 5，即 20 字节头部)
        header_len = 20 + len(options_bytes)
        data_offset = (header_len + 3) // 4  # 向上取整到 4 字节边界
        if data_offset < 5:
            data_offset = 5
        
        # 填充 Options 到 4 字节边界
        padding_len = data_offset * 4 - header_len
        if padding_len > 0:
            options_bytes += b'\x00' * padding_len
        
        tcp_fields = [
            {'name': 'Source Port', 'value': str(src_port), 'illegal': 'srcport' in illegal_fields},
            {'name': 'Dest Port', 'value': str(dst_port), 'illegal': 'dstport' in illegal_fields},
            {'name': 'Sequence Number', 'value': f'0x{seq:08X}', 'illegal': 'seq' in illegal_fields},
            {'name': 'Ack Number', 'value': f'0x{ack:08X}', 'illegal': 'ack' in illegal_fields},
            {'name': 'Data Offset', 'value': str(data_offset), 'illegal': False},
            {'name': 'Flags', 'value': f'0x{flags:02X}', 'illegal': 'flags' in illegal_fields},
            {'name': 'Window Size', 'value': str(window), 'illegal': 'window_size' in illegal_fields},
            {'name': 'Checksum', 'value': f'0x{checksum:04X}', 'illegal': 'checksum' in illegal_fields},
            {'name': 'Urgent Pointer', 'value': '0', 'illegal': False},
        ]
        
        # 如果有 Options，添加到字段列表
        if options_bytes:
            tcp_fields.append({
                'name': 'Options', 
                'value': options if options else options_bytes.hex(), 
                'illegal': 'options' in illegal_fields
            })
        
        layers.append({'name': 'TCP', 'fields': tcp_fields})
        
        # 构建字节
        packet_bytes = struct.pack('>HHIIHHHH',
            src_port,
            dst_port,
            seq,
            ack,
            (data_offset << 12) | flags,  # Data offset + flags
            window,
            checksum,
            0  # Urgent pointer
        )
        
        # 添加 Options
        if options_bytes:
            packet_bytes += options_bytes
        
        return {
            'success': True,
            'packet_hex': packet_bytes.hex(),
            'packet_bytes': packet_bytes,
            'layers': layers,
            'error': None
        }
    
    def _build_udp(self, fields, illegal_fields):
        """构建 UDP 报文"""
        layers = []
        
        src_port = self._parse_value(fields.get('srcport') or '12345')
        dst_port = self._parse_value(fields.get('dstport') or '53')
        length = 8  # UDP header length
        checksum = self._parse_value(fields.get('checksum') or '0')
        
        # 对于非法字段，截断值以适应 struct 格式
        if 'srcport' in illegal_fields:
            src_port = src_port & 0xFFFF
        if 'dstport' in illegal_fields:
            dst_port = dst_port & 0xFFFF
        
        udp_fields = [
            {'name': 'Source Port', 'value': str(src_port), 'illegal': 'srcport' in illegal_fields},
            {'name': 'Dest Port', 'value': str(dst_port), 'illegal': 'dstport' in illegal_fields},
            {'name': 'Length', 'value': str(length), 'illegal': False},
            {'name': 'Checksum', 'value': f'0x{checksum:04X}', 'illegal': 'checksum' in illegal_fields},
        ]
        layers.append({'name': 'UDP', 'fields': udp_fields})
        
        packet_bytes = struct.pack('>HHHH', src_port, dst_port, length, checksum)
        
        return {
            'success': True,
            'packet_hex': packet_bytes.hex(),
            'packet_bytes': packet_bytes,
            'layers': layers,
            'error': None
        }
    
    def _build_icmp(self, fields, illegal_fields):
        """构建 ICMP 报文"""
        layers = []
        
        icmp_type = self._parse_value(fields.get('type') or '8')
        code = self._parse_value(fields.get('code') or '0')
        checksum = self._parse_value(fields.get('checksum') or '0')
        ident = self._parse_value(fields.get('id') or '0x1234')
        seq = self._parse_value(fields.get('seq') or '1')
        
        icmp_fields = [
            {'name': 'Type', 'value': str(icmp_type), 'illegal': 'type' in illegal_fields},
            {'name': 'Code', 'value': str(code), 'illegal': 'code' in illegal_fields},
            {'name': 'Checksum', 'value': f'0x{checksum:04X}', 'illegal': 'checksum' in illegal_fields},
            {'name': 'Identifier', 'value': f'0x{ident:04X}', 'illegal': 'id' in illegal_fields},
            {'name': 'Sequence Number', 'value': str(seq), 'illegal': 'seq' in illegal_fields},
        ]
        layers.append({'name': 'ICMP', 'fields': icmp_fields})
        
        packet_bytes = struct.pack('>BBHHH', icmp_type, code, checksum, ident, seq)
        
        return {
            'success': True,
            'packet_hex': packet_bytes.hex(),
            'packet_bytes': packet_bytes,
            'layers': layers,
            'error': None
        }
    
    def _build_someip(self, fields, illegal_fields):
        """构建 SOME/IP 报文"""
        layers = []
        
        service = self._parse_value(fields.get('service') or '0x1234')
        method = self._parse_value(fields.get('method') or '0x5678')
        client = self._parse_value(fields.get('client') or '0x0001')
        session = self._parse_value(fields.get('session') or '0x0001')
        proto_ver = self._parse_value(fields.get('proto_ver') or '0x01')
        iface_ver = self._parse_value(fields.get('iface_ver') or '0x01')
        msg_type = self._parse_value(fields.get('msg_type') or '0x00')
        retcode = self._parse_value(fields.get('retcode') or '0x00')
        
        someip_fields = [
            {'name': 'Service ID', 'value': f'0x{service:04X}', 'illegal': 'service' in illegal_fields},
            {'name': 'Method ID', 'value': f'0x{method:04X}', 'illegal': 'method' in illegal_fields},
            {'name': 'Client ID', 'value': f'0x{client:04X}', 'illegal': 'client' in illegal_fields},
            {'name': 'Session ID', 'value': f'0x{session:04X}', 'illegal': 'session' in illegal_fields},
            {'name': 'Protocol Version', 'value': f'0x{proto_ver:02X}', 'illegal': 'proto_ver' in illegal_fields},
            {'name': 'Interface Version', 'value': f'0x{iface_ver:02X}', 'illegal': 'iface_ver' in illegal_fields},
            {'name': 'Message Type', 'value': f'0x{msg_type:02X}', 'illegal': 'msg_type' in illegal_fields},
            {'name': 'Return Code', 'value': f'0x{retcode:02X}', 'illegal': 'retcode' in illegal_fields},
        ]
        layers.append({'name': 'SOME/IP', 'fields': someip_fields})
        
        # SOME/IP header: 16 bytes
        message_id = (service << 16) | method
        request_id = (client << 16) | session
        length = 8  # Payload length
        
        packet_bytes = struct.pack('>IIIBBBB',
            message_id,
            length,
            request_id,
            proto_ver,
            iface_ver,
            msg_type,
            retcode
        )
        
        return {
            'success': True,
            'packet_hex': packet_bytes.hex(),
            'packet_bytes': packet_bytes,
            'layers': layers,
            'error': None
        }
    
    def _build_someip_sd(self, fields, illegal_fields):
        """构建 SOME/IP-SD (Service Discovery) 报文
        
        SOME/IP-SD 格式：
        - SOME/IP Header (16 bytes)
        - SD Flags (1 byte) + Reserved (1 byte)
        - Entries Array Length (4 bytes) + Entries Array
        - Options Array Length (4 bytes) + Options Array
        """
        layers = []
        
        # SOME/IP-SD 固定使用 Service ID 0xFFFF, Method ID 0x8100
        service = self._parse_value(fields.get('service') or '0xFFFF')
        method = 0x8100  # 固定为 SD 方法
        client = self._parse_value(fields.get('client') or '0x0001')
        session = self._parse_value(fields.get('session') or '0x0001')
        proto_ver = self._parse_value(fields.get('proto_ver') or '0x01')
        iface_ver = self._parse_value(fields.get('iface_ver') or '0x01')
        msg_type = self._parse_value(fields.get('msg_type') or '0x02')  # Notification 类型
        retcode = self._parse_value(fields.get('retcode') or '0x00')
        
        # SD 特有字段
        flags = self._parse_value(fields.get('flags') or '0xC0')
        entry_type = self._parse_value(fields.get('entry_type') or '0x01')  # 0x01=OfferService
        sd_service_id = self._parse_value(fields.get('sd_service_id') or '0x1234')
        instance_id = self._parse_value(fields.get('instance_id') or '0x0001')
        ttl = self._parse_value(fields.get('ttl') or '0x03')
        option_type = self._parse_value(fields.get('option_type') or '0x04')  # 0x04=IPv4 Endpoint
        
        # 对于非法字段，截断值以适应 struct 格式
        if 'service' in illegal_fields:
            service = service & 0xFFFF
        if 'client' in illegal_fields:
            client = client & 0xFFFF
        if 'session' in illegal_fields:
            session = session & 0xFFFF
        if 'proto_ver' in illegal_fields:
            proto_ver = proto_ver & 0xFF
        if 'iface_ver' in illegal_fields:
            iface_ver = iface_ver & 0xFF
        if 'msg_type' in illegal_fields:
            msg_type = msg_type & 0xFF
        if 'retcode' in illegal_fields:
            retcode = retcode & 0xFF
        if 'flags' in illegal_fields:
            flags = flags & 0xFF
        if 'entry_type' in illegal_fields:
            entry_type = entry_type & 0xFF
        if 'sd_service_id' in illegal_fields:
            sd_service_id = sd_service_id & 0xFFFF
        if 'instance_id' in illegal_fields:
            instance_id = instance_id & 0xFFFF
        if 'ttl' in illegal_fields:
            ttl = ttl & 0xFFFFFF
        if 'option_type' in illegal_fields:
            option_type = option_type & 0xFF
        
        someip_fields = [
            {'name': 'Service ID', 'value': f'0x{service:04X}', 'illegal': 'service' in illegal_fields},
            {'name': 'Method ID (SD)', 'value': f'0x{method:04X}', 'illegal': False},
            {'name': 'Client ID', 'value': f'0x{client:04X}', 'illegal': 'client' in illegal_fields},
            {'name': 'Session ID', 'value': f'0x{session:04X}', 'illegal': 'session' in illegal_fields},
            {'name': 'Protocol Version', 'value': f'0x{proto_ver:02X}', 'illegal': 'proto_ver' in illegal_fields},
            {'name': 'Interface Version', 'value': f'0x{iface_ver:02X}', 'illegal': 'iface_ver' in illegal_fields},
            {'name': 'Message Type', 'value': f'0x{msg_type:02X}', 'illegal': 'msg_type' in illegal_fields},
            {'name': 'Return Code', 'value': f'0x{retcode:02X}', 'illegal': 'retcode' in illegal_fields},
        ]
        
        # SD 字段
        sd_fields = [
            {'name': 'SD Flags', 'value': f'0x{flags:02X}', 'illegal': 'flags' in illegal_fields},
            {'name': 'Entry Type', 'value': f'0x{entry_type:02X}', 'illegal': 'entry_type' in illegal_fields},
            {'name': 'SD Service ID', 'value': f'0x{sd_service_id:04X}', 'illegal': 'sd_service_id' in illegal_fields},
            {'name': 'Instance ID', 'value': f'0x{instance_id:04X}', 'illegal': 'instance_id' in illegal_fields},
            {'name': 'TTL', 'value': f'0x{ttl:06X}', 'illegal': 'ttl' in illegal_fields},
            {'name': 'Option Type', 'value': f'0x{option_type:02X}', 'illegal': 'option_type' in illegal_fields},
        ]
        
        layers.append({'name': 'SOME/IP', 'fields': someip_fields})
        layers.append({'name': 'SOME/IP-SD', 'fields': sd_fields})
        
        # SOME/IP-SD 报文构建
        # 1. SOME/IP Header (16 bytes)
        message_id = (service << 16) | method
        request_id = (client << 16) | session
        
        # 2. SD Payload: flags(1) + reserved(1) + entries_len(4) + entries(N) + options_len(4) + options(N)
        sd_payload = struct.pack('BB', flags, 0x00)  # flags + reserved
        
        # Entry: type(1) + flags(1) + service_id(2) + instance_id(2) + major_ver(1) + ttl(3) + minor_ver(4) = 16 bytes
        entry_bytes = struct.pack('>BHHHBI',
            entry_type,  # entry type
            0x0000,      # entry flags
            sd_service_id,
            instance_id,
            iface_ver,   # major version
            ttl,         # TTL (3 bytes, packed as I but masked)
        )
        # Fix TTL to 3 bytes
        entry_bytes = struct.pack('>BHHHB', entry_type, 0x0000, sd_service_id, instance_id, iface_ver)
        entry_bytes += struct.pack('>I', ttl & 0xFFFFFF)[1:4]  # 3 bytes TTL
        entry_bytes += struct.pack('>I', 0x00000000)  # minor version (4 bytes)
        
        entries_len = len(entry_bytes)
        sd_payload += struct.pack('>I', entries_len) + entry_bytes
        
        # Option: type(1) + length(1) + ip(4) + proto(1) + port(2) = 9 bytes
        option_ip = self._parse_ip(fields.get('option_ip') or '192.168.1.1')
        option_port = self._parse_value(fields.get('option_port') or '30509')
        option_proto = self._parse_value(fields.get('option_proto') or '0x06')  # TCP=6
        
        option_bytes = struct.pack('BB', option_type, 0x09) + option_ip + struct.pack('BH', option_proto & 0xFF, option_port & 0xFFFF)
        options_len = len(option_bytes)
        sd_payload += struct.pack('>I', options_len) + option_bytes
        
        # Total payload length for SOME/IP header
        length = len(sd_payload)
        
        packet_bytes = struct.pack('>IIIBBBB',
            message_id,
            length,
            request_id,
            proto_ver,
            iface_ver,
            msg_type,
            retcode
        ) + sd_payload
        
        return {
            'success': True,
            'packet_hex': packet_bytes.hex(),
            'packet_bytes': packet_bytes,
            'layers': layers,
            'error': None
        }
    
    def _build_doip(self, fields, illegal_fields):
        """构建 DoIP 报文"""
        layers = []
        
        version = self._parse_value(fields.get('version') or '0x02')
        inv_version = self._parse_value(fields.get('inv_version') or '0xFD')
        payload_type = self._parse_value(fields.get('payload_type') or '0x0001')
        
        doip_fields = [
            {'name': 'Version', 'value': f'0x{version:02X}', 'illegal': 'version' in illegal_fields},
            {'name': 'Inverse Version', 'value': f'0x{inv_version:02X}', 'illegal': 'inv_version' in illegal_fields},
            {'name': 'Payload Type', 'value': f'0x{payload_type:04X}', 'illegal': 'payload_type' in illegal_fields},
            {'name': 'Payload Length', 'value': '0', 'illegal': False},
        ]
        layers.append({'name': 'DoIP', 'fields': doip_fields})
        
        # DoIP header: 8 bytes
        packet_bytes = struct.pack('>BBHI', version, inv_version, payload_type, 0)
        
        return {
            'success': True,
            'packet_hex': packet_bytes.hex(),
            'packet_bytes': packet_bytes,
            'layers': layers,
            'error': None
        }
    
    def assemble_multi(self, protocols, all_fields, illegal_fields_map=None, illegal_values_map=None):
        """
        多协议组装 - 按协议栈顺序逐层封装
        
        Args:
            protocols: 协议列表，按协议栈顺序如 ['IP', 'TCP']
            all_fields: {protocol: {field_name: value}} 所有字段值
            illegal_fields_map: {protocol: [field_name]} 非法字段列表
            illegal_values_map: {protocol: {field_name: value}} 非法字段值
            
        Returns:
            dict: {success, packet_hex, packet_bytes, layers, error}
        """
        illegal_fields_map = illegal_fields_map or {}
        illegal_values_map = illegal_values_map or {}
        
        if not protocols or len(protocols) == 0:
            return {
                'success': False,
                'error': '未选择任何协议',
                'packet_hex': '',
                'packet_bytes': [],
                'layers': []
            }
        
        # 如果只有一个协议，回退到单协议组装
        if len(protocols) == 1:
            protocol = protocols[0]
            fields = all_fields.get(protocol, {})
            illegal_fields = illegal_fields_map.get(protocol, [])
            illegal_values = illegal_values_map.get(protocol, {})
            return self.assemble(protocol, fields, illegal_fields, illegal_values)
        
        # 使用 Scapy 构建多协议报文
        try:
            from .scapy_sender import get_scapy_sender
            scapy_sender = get_scapy_sender()
            
            result = scapy_sender.build_multi_protocol_packet(
                protocols, all_fields, illegal_fields_map, illegal_values_map
            )
            
            if result['success']:
                # 构建显示层信息（调用各协议的 builder 获取字段详情）
                display_layers = []
                for protocol in protocols:
                    fields = all_fields.get(protocol, {})
                    illegal_fields = illegal_fields_map.get(protocol, [])
                    illegal_values = illegal_values_map.get(protocol, {})
                    
                    # 合并非法值
                    merged_fields = dict(fields)
                    for f in illegal_fields:
                        if f in illegal_values:
                            merged_fields[f] = illegal_values[f]
                    
                    # 去前缀
                    prefix_map = {
                        'TCP': 'TCP.', 'UDP': 'UDP.', 'IP': 'IP.', 'ICMP': 'ICMP.',
                        'ARP': 'ARP.', 'SOMEIP': 'SOMEIP.', 'SOMEIP-SD': 'SOMEIP-SD.', 'DOIP': 'DOIP.'
                    }
                    prefix = prefix_map.get(protocol, '')
                    if prefix:
                        clean_fields = {}
                        for k, v in merged_fields.items():
                            if k.startswith(prefix):
                                clean_fields[k[len(prefix):]] = v
                            else:
                                clean_fields[k] = v
                        merged_fields = clean_fields
                        illegal_fields = [f[len(prefix):] if f.startswith(prefix) else f for f in illegal_fields]
                    
                    builder = self.protocol_builders.get(protocol)
                    if builder:
                        try:
                            build_result = builder(merged_fields, illegal_fields)
                            if build_result and 'layers' in build_result:
                                display_layers.extend(build_result['layers'])
                        except Exception:
                            pass
                
                result['layers'] = display_layers
            
            return result
            
        except Exception as e:
            return {
                'success': False,
                'error': f'多协议组装失败: {str(e)}',
                'packet_hex': '',
                'packet_bytes': [],
                'layers': []
            }
    
    def clear_cache(self):
        """清理缓存"""
        # 目前无需清理，保留接口供将来使用
        pass


# 全局实例
assembler = None

def get_assembler():
    """获取全局报文组装器"""
    global assembler
    if assembler is None:
        assembler = PacketAssembler()
    return assembler
