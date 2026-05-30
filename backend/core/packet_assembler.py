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
        except:
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
            except:
                return False, f'{field_name}包含无效数字: {part}'
        
        return True, ip_str
    
    def _validate_u8(self, value, field_name='值'):
        """验证8位无符号整数"""
        try:
            num = self._parse_value(value, 0)
            if num < 0 or num > 255:
                return False, f'{field_name}必须在 0-255 之间，当前值: {num}'
            return True, num
        except:
            return False, f'{field_name}必须是有效的数字，当前值: {value}'
    
    def _validate_u16(self, value, field_name='值'):
        """验证16位无符号整数"""
        try:
            num = self._parse_value(value, 0)
            if num < 0 or num > 65535:
                return False, f'{field_name}必须在 0-65535 之间，当前值: {num}'
            return True, num
        except:
            return False, f'{field_name}必须是有效的数字，当前值: {value}'
    
    def _validate_u32(self, value, field_name='值'):
        """验证32位无符号整数"""
        try:
            num = self._parse_value(value, 0)
            if num < 0 or num > 4294967295:
                return False, f'{field_name}必须在 0-4294967295 之间，当前值: {num}'
            return True, num
        except:
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
            except:
                return default
        
        # 十进制
        try:
            return int(value_str)
        except:
            return default
    
    def _parse_ip(self, ip_str):
        """解析 IP 地址为字节"""
        try:
            parts = ip_str.split('.')
            return bytes([int(p) for p in parts])
        except:
            return bytes([192, 168, 1, 1])  # 默认
    
    def _build_arp(self, fields, illegal_fields):
        """构建 ARP 报文"""
        layers = []
        
        # ARP 字段
        proto_type = self._parse_value(fields.get('proto.type') or '0x0800')
        opcode = self._parse_value(fields.get('opcode') or '1')
        src_mac = fields.get('src.hw_mac') or '00:11:22:33:44:55'
        dst_mac = fields.get('dst.hw_mac') or '00:00:00:00:00:00'
        
        arp_fields = [
            {'name': 'Hardware Type', 'value': '0x0001 (Ethernet)', 'illegal': False},
            {'name': 'Protocol Type', 'value': f'0x{proto_type:04X}', 'illegal': 'proto.type' in illegal_fields},
            {'name': 'Hardware Size', 'value': '6', 'illegal': False},
            {'name': 'Protocol Size', 'value': '4', 'illegal': False},
            {'name': 'Opcode', 'value': f'0x{opcode:04X}', 'illegal': 'opcode' in illegal_fields},
            {'name': 'Sender MAC', 'value': src_mac, 'illegal': 'src.hw_mac' in illegal_fields},
            {'name': 'Target MAC', 'value': dst_mac, 'illegal': 'dst.hw_mac' in illegal_fields},
        ]
        layers.append({'name': 'ARP', 'fields': arp_fields})
        
        # 构建字节（简化）
        packet_bytes = struct.pack('>HHBBH', 0x0001, proto_type, 6, 4, opcode)
        
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
        
        ip_fields = [
            {'name': 'Version', 'value': str(version), 'illegal': 'version' in illegal_fields},
            {'name': 'IHL', 'value': '5', 'illegal': False},
            {'name': 'TOS', 'value': f'0x{tos:02X}', 'illegal': 'tos' in illegal_fields},
            {'name': 'Total Length', 'value': '20', 'illegal': False},
            {'name': 'Identification', 'value': f'0x{ident:04X}', 'illegal': 'id' in illegal_fields},
            {'name': 'Flags', 'value': '0x0000', 'illegal': False},
            {'name': 'TTL', 'value': str(ttl), 'illegal': 'ttl' in illegal_fields},
            {'name': 'Protocol', 'value': 'TCP (6)', 'illegal': False},
            {'name': 'Checksum', 'value': f'0x{checksum:04X}', 'illegal': 'checksum' in illegal_fields},
            {'name': 'Source IP', 'value': fields.get('src', '192.168.1.100'), 'illegal': 'src' in illegal_fields},
            {'name': 'Dest IP', 'value': fields.get('dst', '192.168.1.1'), 'illegal': 'dst' in illegal_fields},
        ]
        layers.append({'name': 'IP', 'fields': ip_fields})
        
        # 构建字节
        packet_bytes = struct.pack('>BBHHHBBH',
            (version << 4) | 5,  # Version + IHL
            tos,
            20,  # Total length
            ident,
            0x0000,  # Flags + Fragment offset
            ttl,
            6,  # Protocol (TCP)
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
            except:
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
        
        SOME/IP-SD 是 SOME/IP 的服务发现协议，Method ID 固定为 0x8100
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
        flags = self._parse_value(fields.get('sd_flags') or '0x00')
        
        # 对于非法字段，截断值以适应 struct 格式
        if 'service' in illegal_fields:
            service = service & 0xFFFF  # 截断到 16 位
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
        if 'sd_flags' in illegal_fields:
            flags = flags & 0xFF
        
        someip_fields = [
            {'name': 'Service ID', 'value': f'0x{service:04X}', 'illegal': 'service' in illegal_fields},
            {'name': 'Method ID (SD)', 'value': f'0x{method:04X}', 'illegal': False},
            {'name': 'Client ID', 'value': f'0x{client:04X}', 'illegal': 'client' in illegal_fields},
            {'name': 'Session ID', 'value': f'0x{session:04X}', 'illegal': 'session' in illegal_fields},
            {'name': 'Protocol Version', 'value': f'0x{proto_ver:02X}', 'illegal': 'proto_ver' in illegal_fields},
            {'name': 'Interface Version', 'value': f'0x{iface_ver:02X}', 'illegal': 'iface_ver' in illegal_fields},
            {'name': 'Message Type', 'value': f'0x{msg_type:02X}', 'illegal': 'msg_type' in illegal_fields},
            {'name': 'Return Code', 'value': f'0x{retcode:02X}', 'illegal': 'retcode' in illegal_fields},
            {'name': 'SD Flags', 'value': f'0x{flags:02X}', 'illegal': 'sd_flags' in illegal_fields},
        ]
        layers.append({'name': 'SOME/IP-SD', 'fields': someip_fields})
        
        # SOME/IP-SD header: 16 bytes + 1 byte SD flags
        message_id = (service << 16) | method
        request_id = (client << 16) | session
        length = 9  # Payload length (8 + 1 byte flags)
        
        packet_bytes = struct.pack('>IIIBBBB',
            message_id,
            length,
            request_id,
            proto_ver,
            iface_ver,
            msg_type,
            retcode
        ) + struct.pack('B', flags)  # SD flags
        
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
