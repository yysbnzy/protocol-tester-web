# -*- coding: utf-8 -*-
"""TLS Record 组包、协议栈约束和本地 TCP Socket 回归。"""

import re
import socket
import threading

import pytest
from scapy.all import IP, TCP, Raw

from app import app, init_app, limiter
from backend.core.packet_assembler import PacketAssembler, build_tls_record
from backend.core.scapy_sender import ScapyRawSender


init_app()


@pytest.fixture
def client():
    app.config['TESTING'] = True
    limiter.enabled = False
    with app.test_client() as test_client:
        yield test_client


@pytest.fixture
def assembler():
    return PacketAssembler()


@pytest.fixture
def sender():
    return ScapyRawSender()


@pytest.mark.parametrize('payload,expected', [
    ('', '1603030000'),
    ('01020304', '160303000401020304'),
    ('hex:01 02 03 04', '160303000401020304'),
    ('0x01020304', '160303000401020304'),
    ('ascii:TLS', '1603030003544c53'),
])
def test_tls_record_payload_formats(assembler, payload, expected):
    result = assembler.assemble('TLS', {
        'content_type': '0x16 (Handshake)', 'version': '0x0303', 'payload': payload,
    })
    assert result['success'] is True, result
    assert result['packet_hex'] == expected


@pytest.mark.parametrize('content_type,version,payload,expected', [
    ('0x15', '0x0303', '0100', '15030300020100'),
    ('0x17', '0x0301', 'aabb', '1703010002aabb'),
])
def test_tls_record_content_type_and_version(assembler, content_type, version, payload, expected):
    result = assembler.assemble('TLS', {
        'content_type': content_type, 'version': version, 'payload': payload,
    })
    assert result['success'] is True, result
    assert result['packet_hex'] == expected


def test_tls_illegal_length_overrides_actual_payload_length(assembler):
    result = assembler.assemble('TLS', {
        'content_type': '0x16', 'version': '0x0303',
        'length': '0', 'payload': '01020304',
    }, ['length'])
    assert result['success'] is True, result
    assert result['packet_hex'] == '160303000001020304'


def test_tls_illegal_payload_allows_literal_text(assembler):
    result = assembler.assemble('TLS', {
        'content_type': '0x16', 'version': '0x0303', 'payload': 'INVALID',
    }, ['payload'])
    assert result['success'] is True, result
    assert result['packet_hex'] == '1603030007494e56414c4944'


def test_tls_legal_payload_rejects_non_hex_text(assembler):
    result = assembler.assemble('TLS', {
        'content_type': '0x16', 'version': '0x0303', 'payload': 'INVALID',
    })
    assert result['success'] is False
    assert 'Payload 格式无效' in result['error']


@pytest.mark.parametrize('field,value', [
    ('content_type', '0x100'),
    ('version', '0x10000'),
    ('length', '0x10000'),
])
def test_tls_field_width_errors_are_explicit(field, value):
    fields = {'content_type': 0x16, 'version': 0x0303, 'length': 4}
    fields[field] = value
    with pytest.raises(ValueError, match=f'TLS .*必须在 0-'):
        build_tls_record(
            int(fields['content_type'], 0) if isinstance(fields['content_type'], str) else fields['content_type'],
            int(fields['version'], 0) if isinstance(fields['version'], str) else fields['version'],
            b'',
            int(fields['length'], 0) if isinstance(fields['length'], str) else fields['length'],
        )


def test_single_tls_auto_adds_ipv4_tcp_443(sender):
    result = sender.build_multi_protocol_packet(['TLS'], {
        'TLS': {'payload': '01020304'},
    })
    assert result['success'] is True, result
    packet = IP(bytes(result['packet_bytes']))
    assert packet[TCP].dport == 443
    assert bytes(packet[Raw].load).hex() == '160303000401020304'


def test_explicit_tls_stack_has_one_payload(sender):
    result = sender.build_multi_protocol_packet(['IP', 'TCP', 'TLS'], {
        'IP': {'src': '192.0.2.1', 'dst': '192.0.2.2'},
        'TCP': {'dstport': '8443', 'flags': 'PA'},
        'TLS': {'payload': '01020304'},
    })
    assert result['success'] is True, result
    packet = IP(bytes(result['packet_bytes']))
    assert packet[TCP].dport == 8443
    assert bytes(packet[Raw].load) == bytes.fromhex('160303000401020304')


@pytest.mark.parametrize('protocols,error', [
    (['IP', 'UDP', 'TLS'], 'TLS 使用 TCP'),
    (['IP', 'TLS'], '必须选择 TCP'),
    (['IP', 'ICMP', 'TLS'], '必须选择 TCP|不能封装在 ICMP'),
    (['IP', 'TCP', 'TLS', 'DOIP'], '只能选择一个应用层协议'),
])
def test_tls_rejects_invalid_stacks(sender, protocols, error):
    result = sender.build_multi_protocol_packet(protocols, {})
    assert result['success'] is False
    assert re.search(error, result['error'])


def test_tls_defaults_api(client):
    response = client.get('/api/defaults')
    body = response.get_json()
    assert response.status_code == 200
    assert body['legal']['TLS']['TLS.content_type'] == '0x16 (Handshake)'
    assert body['legal']['TLS']['TLS.version'] == '0x0303'
    assert body['legal']['TLS']['TLS.length'] == 'auto'


def _start_receiver(expected_bytes):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('127.0.0.1', 0))
    server.listen(1)
    server.settimeout(5)
    result = {'data': b'', 'error': None}

    def receive():
        conn = None
        try:
            conn, _ = server.accept()
            conn.settimeout(3)
            chunks = []
            while sum(map(len, chunks)) < expected_bytes:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
            result['data'] = b''.join(chunks)
        except Exception as exc:
            result['error'] = str(exc)
        finally:
            if conn is not None:
                conn.close()
            server.close()

    thread = threading.Thread(target=receive, daemon=True)
    thread.start()
    return server.getsockname()[1], result, thread


def test_tls_record_socket_loopback_has_no_ip_tcp_headers(client):
    expected = bytes.fromhex('160303000401020304')
    port, received, thread = _start_receiver(len(expected))
    build = client.post('/api/assemble', json={
        'protocol': 'TLS',
        'fields': {'content_type': '0x16', 'version': '0x0303', 'payload': '01020304'},
        'illegal_fields': [],
    })
    assert build.get_json()['packet_hex'] == expected.hex()

    response = client.post('/api/tcp/send', json={
        'target_ip': '127.0.0.1',
        'target_port': port,
        'packet_data': {'payload': build.get_json()['packet_hex']},
        'count': 1,
        'interval_ms': 0,
        'mode': 'socket',
    })
    thread.join(timeout=5)
    body = response.get_json()
    assert body['success'] is True, body
    assert received['error'] is None
    assert received['data'] == expected
