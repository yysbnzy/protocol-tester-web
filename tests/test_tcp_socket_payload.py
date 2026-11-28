# -*- coding: utf-8 -*-
"""TCP Socket 仅发送应用层 Payload 的回归测试。"""

import json
import socket
import threading
from unittest.mock import Mock, patch

import pytest

from app import app, init_app, limiter
from routes.tcp_routes import _decode_socket_payload


init_app()


TLS_PAYLOAD = bytes.fromhex('16 03 01 00 02 01 00')


@pytest.fixture
def client():
    app.config['TESTING'] = True
    limiter.enabled = False
    with app.test_client() as test_client:
        yield test_client


def _start_receiver(expected_bytes):
    """启动本地 TCP 接收端，返回实际收到的应用层字节。"""
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
        except Exception as exc:  # 测试断言中输出真实接收异常
            result['error'] = str(exc)
        finally:
            if conn is not None:
                conn.close()
            server.close()

    thread = threading.Thread(target=receive, daemon=True)
    thread.start()
    return server.getsockname()[1], result, thread


@pytest.mark.parametrize('packet_data,expected', [
    ({'srcport': '12345', 'flags': '0x00', 'payload': '16 03 01 00 02 01 00'}, TLS_PAYLOAD),
    ({'hex': 'FF FF'}, b'\xff\xff'),
    ({'text': 'ascii:TLS'}, b'TLS'),
    ({'payload': 'ascii:TLS'}, b'TLS'),
    ('test', b'test'),
    ([0x16, 0x03, 0x01], b'\x16\x03\x01'),
])
def test_decode_socket_payload(packet_data, expected):
    assert _decode_socket_payload(packet_data) == expected


@pytest.mark.parametrize('packet_data', [
    {'srcport': '12345', 'flags': '0x00'},
    {'payload': 'hex:0'},
    {'payload': 'hex:GG'},
])
def test_decode_socket_payload_rejects_invalid_input(packet_data):
    with pytest.raises(ValueError):
        _decode_socket_payload(packet_data)


def test_direct_socket_sends_only_hex_payload(client):
    port, received, thread = _start_receiver(len(TLS_PAYLOAD))
    response = client.post('/api/tcp/send', data=json.dumps({
        'target_ip': '127.0.0.1',
        'target_port': port,
        'packet_data': {
            'srcport': '12345',
            'dstport': str(port),
            'seq': '0',
            'ack': '0',
            'flags': '0x00',
            'window_size': '8192',
            'checksum': '0x0000',
            'options': '',
            'payload': TLS_PAYLOAD.hex(' '),
        },
        'count': 1,
        'interval': 0,
    }), content_type='application/json')
    thread.join(timeout=5)

    body = response.get_json()
    assert response.status_code == 200
    assert body['success'] is True, body
    assert body['total_sent'] == len(TLS_PAYLOAD)
    assert received['error'] is None
    assert received['data'] == TLS_PAYLOAD


def test_established_socket_sends_only_payload_not_tcp_header(client):
    port, received, thread = _start_receiver(len(TLS_PAYLOAD))
    handshake = client.post('/api/tcp/handshake', data=json.dumps({
        'target_ip': '127.0.0.1',
        'target_port': port,
        'mode': 'socket',
    }), content_type='application/json')
    handshake_body = handshake.get_json()
    assert handshake_body['success'] is True, handshake_body

    response = client.post('/api/tcp/attack', data=json.dumps({
        'conn_id': handshake_body['conn_id'],
        'packet_data': {
            'srcport': '12345',
            'dstport': str(port),
            'seq': '0',
            'ack': '0',
            'flags': '0x00',
            'window_size': '8192',
            'checksum': '0x0000',
            'options': '',
            'payload': TLS_PAYLOAD.hex(' '),
        },
        'count': 1,
        'interval': 0,
    }), content_type='application/json')
    thread.join(timeout=5)

    body = response.get_json()
    assert response.status_code == 200
    assert body['success'] is True, body
    assert received['error'] is None
    assert received['data'] == TLS_PAYLOAD

    client.post('/api/tcp/close', data=json.dumps({
        'conn_id': handshake_body['conn_id'],
    }), content_type='application/json')


def test_direct_socket_accepts_frontend_interval_ms(client):
    sock = Mock()
    with patch('socket.socket', return_value=sock), \
         patch('routes.tcp_routes.time.sleep') as sleep:
        response = client.post('/api/tcp/send', json={
            'target_ip': '127.0.0.1',
            'target_port': 8080,
            'packet_data': {'payload': '0102'},
            'count': 2,
            'interval_ms': 25,
        })

    body = response.get_json()
    assert body['success'] is True, body
    assert body['success_count'] == 2
    assert body['total_sent'] == 4
    assert sock.sendall.call_count == 2
    sleep.assert_called_once_with(0.025)
