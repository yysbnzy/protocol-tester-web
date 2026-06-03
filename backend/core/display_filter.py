# -*- coding: utf-8 -*-
"""
Wireshark-style Display Filter Engine
显示过滤器引擎 - 支持类似 Wireshark 的过滤语法

支持语法：
- 比较: ip.addr == 192.168.1.1, tcp.port != 80
- 范围: frame.len > 100, tcp.window_size >= 65535
- 包含: ip.src in {192.168.1.0/24}
- 逻辑: && (and), || (or), ! (not)
- 字符串: http.request.uri contains "admin"
"""

import re
import ipaddress
from typing import Any, Dict, List, Optional, Callable
from dataclasses import dataclass
from enum import Enum, auto

class TokenType(Enum):
    """词法分析令牌类型"""
    FIELD = auto()          # 字段名，如 ip.addr
    STRING = auto()         # 字符串
    NUMBER = auto()         # 数字
    IP_ADDR = auto()        # IP地址
    OPERATOR = auto()       # 操作符: ==, !=, >, <, >=, <=
    LOGICAL = auto()        # 逻辑: &&, ||, !
    LPAREN = auto()         # (
    RPAREN = auto()         # )
    IN = auto()             # in 关键字
    CONTAINS = auto()       # contains 关键字
    SET = auto()            # { } 集合
    EOF = auto()            # 结束

@dataclass
class Token:
    """词法令牌"""
    type: TokenType
    value: Any
    pos: int = 0

class DisplayFilterLexer:
    """显示过滤器词法分析器"""
    
    # 操作符
    OPERATORS = {
        '==': 'eq', '!=': 'ne', '>': 'gt', '<': 'lt',
        '>=': 'ge', '<=': 'le'
    }
    
    # 逻辑符
    LOGICALS = {'&&': 'and', '||': 'or', '!': 'not'}
    
    # 关键字
    KEYWORDS = {'in': TokenType.IN, 'contains': TokenType.CONTAINS}
    
    def __init__(self, text: str):
        self.text = text
        self.pos = 0
        self.length = len(text)
    
    def tokenize(self) -> List[Token]:
        """词法分析"""
        tokens = []
        
        while self.pos < self.length:
            char = self.text[self.pos]
            
            # 跳过空白
            if char.isspace():
                self.pos += 1
                continue
            
            # 括号
            if char == '(':
                tokens.append(Token(TokenType.LPAREN, '(', self.pos))
                self.pos += 1
                continue
            if char == ')':
                tokens.append(Token(TokenType.RPAREN, ')', self.pos))
                self.pos += 1
                continue
            
            # 集合 { }
            if char == '{':
                tokens.append(self._read_set())
                continue
            
            # 字符串 " " 或 ' '
            if char in '"\'':
                tokens.append(self._read_string())
                continue
            
            # 操作符和逻辑符
            if char in '=!<>&|':
                op = self._read_operator()
                if op in self.LOGICALS:
                    tokens.append(Token(TokenType.LOGICAL, op, self.pos))
                else:
                    tokens.append(Token(TokenType.OPERATOR, op, self.pos))
                continue
            
            # 数字
            if char.isdigit() or (char == '.' and self._peek().isdigit()):
                token = self._read_number_or_ip()
                tokens.append(token)
                continue
            
            # 字段名或关键字
            if char.isalpha() or char == '_':
                token = self._read_field_or_keyword()
                tokens.append(token)
                continue
            
            # 未知字符，跳过
            self.pos += 1
        
        tokens.append(Token(TokenType.EOF, None, self.pos))
        return tokens
    
    def _read_string(self) -> Token:
        """读取字符串"""
        quote = self.text[self.pos]
        start = self.pos
        self.pos += 1
        value = ''
        
        while self.pos < self.length and self.text[self.pos] != quote:
            if self.text[self.pos] == '\\' and self.pos + 1 < self.length:
                self.pos += 1
            value += self.text[self.pos]
            self.pos += 1
        
        self.pos += 1  # 跳过结束引号
        return Token(TokenType.STRING, value, start)
    
    def _read_operator(self) -> str:
        """读取操作符"""
        two_char = self.text[self.pos:self.pos+2]
        if two_char in ('==', '!=', '>=', '<=', '&&', '||'):
            self.pos += 2
            return two_char
        self.pos += 1
        return self.text[self.pos-1]
    
    def _read_number_or_ip(self) -> Token:
        """读取数字或 IP 地址"""
        start = self.pos
        value = ''
        dot_count = 0
        
        while self.pos < self.length:
            char = self.text[self.pos]
            if char.isdigit():
                value += char
            elif char == '.' and dot_count < 3:
                value += char
                dot_count += 1
            elif char == '/' and dot_count == 3:
                # CIDR 表示法
                value += char
                self.pos += 1
                while self.pos < self.length and self.text[self.pos].isdigit():
                    value += self.text[self.pos]
                    self.pos += 1
                break
            else:
                break
            self.pos += 1
        
        # 判断是 IP 还是数字
        if dot_count == 3:
            try:
                ipaddress.ip_network(value, strict=False)
                return Token(TokenType.IP_ADDR, value, start)
            except ValueError:
                pass
        
        # 尝试解析为数字
        try:
            if '.' in value:
                return Token(TokenType.NUMBER, float(value), start)
            else:
                return Token(TokenType.NUMBER, int(value), start)
        except (ValueError, TypeError):
            return Token(TokenType.STRING, value, start)
    
    def _read_field_or_keyword(self) -> Token:
        """读取字段名或关键字"""
        start = self.pos
        value = ''
        
        while self.pos < self.length:
            char = self.text[self.pos]
            if char.isalnum() or char in '._':
                value += char
                self.pos += 1
            else:
                break
        
        # 检查是否是关键字
        lower = value.lower()
        if lower in self.KEYWORDS:
            return Token(self.KEYWORDS[lower], lower, start)
        
        return Token(TokenType.FIELD, value, start)
    
    def _read_set(self) -> Token:
        """读取集合 { }"""
        start = self.pos
        self.pos += 1  # 跳过 {
        value = ''
        depth = 1
        
        while self.pos < self.length and depth > 0:
            char = self.text[self.pos]
            if char == '{':
                depth += 1
            elif char == '}':
                depth -= 1
                if depth == 0:
                    self.pos += 1
                    break
            value += char
            self.pos += 1
        
        # 解析集合内容
        items = [item.strip() for item in value.split(',') if item.strip()]
        return Token(TokenType.SET, items, start)
    
    def _peek(self) -> str:
        """查看下一个字符"""
        if self.pos + 1 < self.length:
            return self.text[self.pos + 1]
        return ''


@dataclass
class FilterNode:
    """过滤器 AST 节点"""
    type: str
    field: Optional[str] = None
    operator: Optional[str] = None
    value: Any = None
    left: Optional['FilterNode'] = None
    right: Optional['FilterNode'] = None

class DisplayFilterParser:
    """显示过滤器语法分析器"""
    
    def __init__(self, tokens: List[Token]):
        self.tokens = tokens
        self.pos = 0
    
    def parse(self) -> Optional[FilterNode]:
        """解析为 AST"""
        if not self.tokens or self.tokens[0].type == TokenType.EOF:
            return None
        return self._parse_or()
    
    def _current(self) -> Token:
        """当前令牌"""
        if self.pos < len(self.tokens):
            return self.tokens[self.pos]
        return self.tokens[-1]
    
    def _advance(self) -> Token:
        """前进并返回当前令牌"""
        token = self._current()
        self.pos += 1
        return token
    
    def _parse_or(self) -> FilterNode:
        """解析 OR 表达式"""
        left = self._parse_and()
        
        while self._current().type == TokenType.LOGICAL and self._current().value == '||':
            self._advance()
            right = self._parse_and()
            left = FilterNode(type='logical', operator='or', left=left, right=right)
        
        return left
    
    def _parse_and(self) -> FilterNode:
        """解析 AND 表达式"""
        left = self._parse_not()
        
        while self._current().type == TokenType.LOGICAL and self._current().value == '&&':
            self._advance()
            right = self._parse_not()
            left = FilterNode(type='logical', operator='and', left=left, right=right)
        
        return left
    
    def _parse_not(self) -> FilterNode:
        """解析 NOT 表达式"""
        if self._current().type == TokenType.LOGICAL and self._current().value == '!':
            self._advance()
            operand = self._parse_not()
            return FilterNode(type='logical', operator='not', left=operand)
        
        return self._parse_primary()
    
    def _parse_primary(self) -> FilterNode:
        """解析基本表达式"""
        token = self._current()
        
        # 括号分组
        if token.type == TokenType.LPAREN:
            self._advance()
            node = self._parse_or()
            if self._current().type == TokenType.RPAREN:
                self._advance()
            return node
        
        # 字段比较
        if token.type == TokenType.FIELD:
            return self._parse_comparison()
        
        # 默认解析比较
        return self._parse_comparison()
    
    def _parse_comparison(self) -> FilterNode:
        """解析比较表达式"""
        # 可能是字段名或布尔字段
        token = self._advance()
        
        if token.type == TokenType.FIELD:
            field_name = token.value
            
            # 检查是否是布尔字段（没有操作符）
            if self._current().type in (TokenType.LOGICAL, TokenType.RPAREN, TokenType.EOF):
                return FilterNode(type='boolean', field=field_name)
            
            # 读取操作符
            if self._current().type == TokenType.OPERATOR:
                op = self._advance().value
                value_token = self._advance()
                
                if value_token.type in (TokenType.NUMBER, TokenType.STRING, TokenType.IP_ADDR):
                    return FilterNode(type='comparison', field=field_name, 
                                    operator=op, value=value_token.value)
                elif value_token.type == TokenType.SET:
                    return FilterNode(type='membership', field=field_name,
                                    operator=op, value=value_token.value)
            
            elif self._current().type == TokenType.IN:
                self._advance()
                value_token = self._advance()
                if value_token.type == TokenType.SET:
                    return FilterNode(type='membership', field=field_name,
                                    operator='in', value=value_token.value)
            
            elif self._current().type == TokenType.CONTAINS:
                self._advance()
                value_token = self._advance()
                if value_token.type == TokenType.STRING:
                    return FilterNode(type='contains', field=field_name,
                                    operator='contains', value=value_token.value)
        
        # 默认返回真
        return FilterNode(type='boolean', field='_always_true')


class DisplayFilterEngine:
    """
    显示过滤器引擎
    执行 AST 并判断是否匹配报文
    """
    
    def __init__(self, filter_text: str):
        self.filter_text = filter_text
        self.ast = None
        self._compile()
    
    def _compile(self):
        """编译过滤器"""
        if not self.filter_text or self.filter_text.strip() == '':
            self.ast = None
            return
        
        lexer = DisplayFilterLexer(self.filter_text)
        tokens = lexer.tokenize()
        parser = DisplayFilterParser(tokens)
        self.ast = parser.parse()
    
    def match(self, packet_info: Dict) -> bool:
        """
        检查报文是否匹配过滤器
        
        Args:
            packet_info: 报文信息字典，包含所有字段
        
        Returns:
            bool: 是否匹配
        """
        if self.ast is None:
            return True
        
        return self._evaluate(self.ast, packet_info)
    
    def _evaluate(self, node: FilterNode, packet_info: Dict) -> bool:
        """评估 AST 节点"""
        if node.type == 'boolean':
            # 布尔字段检查
            if node.field == '_always_true':
                return True
            
            # 协议名映射（布尔字段检查）
            PROTOCOL_MAP = {
                'tcp': 'TCP', 'udp': 'UDP', 'icmp': 'ICMP', 'arp': 'ARP',
                'doip': 'DOIP', 'someip': 'SOMEIP', 'someip-sd': 'SOMEIP-SD',
                'http': 'HTTP', 'https': 'HTTPS', 'dns': 'DNS',
                'dhcp': 'DHCP', 'ssh': 'SSH', 'ftp': 'FTP',
            }
            
            field_lower = node.field.lower()
            if field_lower in PROTOCOL_MAP:
                proto_name = PROTOCOL_MAP[field_lower]
                pkt_proto = packet_info.get('protocol', '')
                if pkt_proto.upper() == proto_name.upper():
                    return True
                # HTTP 启发式检测：端口 80/8080/8008
                if proto_name == 'HTTP':
                    ports = [packet_info.get('src_port'), packet_info.get('dst_port')]
                    return any(p in (80, 8080, 8008) for p in ports if p not in (None, '-', ''))
                # HTTPS 启发式检测：端口 443/8443
                if proto_name == 'HTTPS':
                    ports = [packet_info.get('src_port'), packet_info.get('dst_port')]
                    return any(p in (443, 8443) for p in ports if p not in (None, '-', ''))
                # DNS 启发式检测：端口 53
                if proto_name == 'DNS':
                    ports = [packet_info.get('src_port'), packet_info.get('dst_port')]
                    return any(p == 53 for p in ports if p not in (None, '-', ''))
                # DHCP 启发式检测：端口 67/68
                if proto_name == 'DHCP':
                    ports = [packet_info.get('src_port'), packet_info.get('dst_port')]
                    return any(p in (67, 68) for p in ports if p not in (None, '-', ''))
                # SSH 启发式检测：端口 22
                if proto_name == 'SSH':
                    ports = [packet_info.get('src_port'), packet_info.get('dst_port')]
                    return any(p == 22 for p in ports if p not in (None, '-', ''))
                # FTP 启发式检测：端口 21
                if proto_name == 'FTP':
                    ports = [packet_info.get('src_port'), packet_info.get('dst_port')]
                    return any(p == 21 for p in ports if p not in (None, '-', ''))
                return False
            
            return self._get_field_value(packet_info, node.field) is not None
        
        elif node.type == 'logical':
            if node.operator == 'and':
                return self._evaluate(node.left, packet_info) and self._evaluate(node.right, packet_info)
            elif node.operator == 'or':
                return self._evaluate(node.left, packet_info) or self._evaluate(node.right, packet_info)
            elif node.operator == 'not':
                return not self._evaluate(node.left, packet_info)
        
        elif node.type == 'comparison':
            field_value = self._get_field_value(packet_info, node.field)
            if field_value is None:
                return False
            
            return self._compare(field_value, node.operator, node.value)
        
        elif node.type == 'membership':
            field_value = self._get_field_value(packet_info, node.field)
            if field_value is None:
                return False
            
            # 检查是否在集合中
            for item in node.value:
                try:
                    # 尝试作为 CIDR 解析
                    network = ipaddress.ip_network(item, strict=False)
                    addr = ipaddress.ip_address(field_value)
                    if addr in network:
                        return True
                except (ValueError, TypeError):
                    # 普通值比较
                    if str(field_value) == str(item):
                        return True
            return False
        
        elif node.type == 'contains':
            field_value = self._get_field_value(packet_info, node.field)
            if field_value is None:
                return False
            return node.value in str(field_value)
        
        return True
    
    def _get_field_value(self, packet_info: Dict, field: str) -> Any:
        """
        获取字段值，支持点号路径
        如 ip.src, tcp.dstport
        """
        # 处理特殊字段映射
        field_map = {
            'ip.addr': ['src_ip', 'dst_ip'],
            'tcp.port': ['src_port', 'dst_port'],
            'udp.port': ['src_port', 'dst_port'],
            'frame.len': 'length',
            'frame.time': 'time',
            'frame.protocol': 'protocol',
        }
        
        if field in field_map:
            mapped = field_map[field]
            if isinstance(mapped, list):
                # 返回第一个存在的值
                for key in mapped:
                    if key in packet_info and packet_info[key] not in (None, '-', ''):
                        return packet_info[key]
                return None
            else:
                return packet_info.get(mapped)
        
        # 直接映射
        direct_map = {
            'ip.src': 'src_ip',
            'ip.dst': 'dst_ip',
            'tcp.srcport': 'src_port',
            'tcp.dstport': 'dst_port',
            'udp.srcport': 'src_port',
            'udp.dstport': 'dst_port',
            'eth.src': 'src_mac',
            'eth.dst': 'dst_mac',
            'eth.type': 'protocol',
            'frame.len': 'length',
            'frame.time': 'time',
            'frame.protocol': 'protocol',
        }
        
        if field in direct_map:
            return packet_info.get(direct_map[field])
        
        # 尝试直接获取
        return packet_info.get(field)
    
    def _compare(self, field_value: Any, operator: str, compare_value: Any) -> bool:
        """比较两个值"""
        # 检查空值
        if field_value is None or field_value == '-' or field_value == '':
            # 空值只匹配 '!=' 和某些特定情况
            if operator == '!=':
                return compare_value not in (None, '-', '')
            return False
        
        # 尝试转换为相同类型
        try:
            if isinstance(compare_value, (int, float)):
                field_value = float(field_value)
        except (ValueError, TypeError):
            pass
        
        op_map = {
            '==': lambda a, b: str(a) == str(b),
            '!=': lambda a, b: str(a) != str(b),
            '>': lambda a, b: float(a) > float(b),
            '<': lambda a, b: float(a) < float(b),
            '>=': lambda a, b: float(a) >= float(b),
            '<=': lambda a, b: float(a) <= float(b),
        }
        
        if operator in op_map:
            try:
                return op_map[operator](field_value, compare_value)
            except (ValueError, TypeError, Exception):
                return False
        
        return False


# ==================== 便捷函数 ====================

def create_filter(filter_text: str) -> DisplayFilterEngine:
    """创建过滤器"""
    return DisplayFilterEngine(filter_text)


def quick_filter(filter_text: str, packet_info: Dict) -> bool:
    """快速过滤检查"""
    engine = DisplayFilterEngine(filter_text)
    return engine.match(packet_info)


# 常用过滤器预设
COMMON_FILTERS = {
    'tcp_only': 'tcp',
    'udp_only': 'udp',
    'icmp_only': 'icmp',
    'arp_only': 'arp',
    'http': 'tcp.port == 80',
    'https': 'tcp.port == 443',
    'dns': 'udp.port == 53',
    'dhcp': 'udp.port == 67 || udp.port == 68',
    'ssh': 'tcp.port == 22',
    'ftp': 'tcp.port == 21',
    'smtp': 'tcp.port == 25',
    'pop3': 'tcp.port == 110',
    'imap': 'tcp.port == 143',
    'mysql': 'tcp.port == 3306',
    'redis': 'tcp.port == 6379',
    'mongodb': 'tcp.port == 27017',
    'doip': 'doip',
    'someip': 'someip',
    'local_traffic': 'ip.src in {10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16}',
    'large_packets': 'frame.len > 1000',
    'small_packets': 'frame.len < 100',
}

__all__ = [
    'DisplayFilterEngine',
    'DisplayFilterLexer',
    'DisplayFilterParser',
    'FilterNode',
    'Token',
    'TokenType',
    'create_filter',
    'quick_filter',
    'COMMON_FILTERS',
]
