# -*- coding: utf-8 -*-
"""真实 TLS 回环：验证握手、协商信息、加密应用数据及失败不回退。"""

import socket
import ssl
import threading
from pathlib import Path
from unittest.mock import patch

import pytest

from app import app, init_app, limiter
from backend.core.send_mode_manager import SendModeManager


init_app()
FIXTURES = Path(__file__).parent / 'fixtures'
CERTFILE = FIXTURES / 'tls-test-cert.pem'
KEYFILE = FIXTURES / 'tls-test-key.pem'


@pytest.fixture
def client():
    app.config['TESTING'] = True
    limiter.enabled = False
    with app.test_client() as test_client:
        yield test_client


def _server_context(minimum=None, maximum=None):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(CERTFILE, KEYFILE)
    if minimum is not None:
        context.minimum_version = minimum
    if maximum is not None:
        context.maximum_version = maximum
    return context


def _start_tls_server(expected_bytes, minimum=None, maximum=None):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('127.0.0.1', 0))
    server.listen(1)
    server.settimeout(5)
    result = {'data': b'', 'version': None, 'cipher': None, 'error': None}

    def receive():
        conn = None
        try:
            raw_conn, _ = server.accept()
            raw_conn.settimeout(5)
            conn = _server_context(minimum, maximum).wrap_socket(
                raw_conn, server_side=True
            )
            result['version'] = conn.version()
            result['cipher'] = conn.cipher()[0]
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


def _start_plain_tcp_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('127.0.0.1', 0))
    server.listen(1)
    server.settimeout(5)
    result = {'data': b'', 'error': None}

    def receive():
        try:
            conn, _ = server.accept()
            conn.settimeout(3)
            result['data'] = conn.recv(4096)
            conn.close()
        except Exception as exc:
            result['error'] = str(exc)
        finally:
            server.close()

    thread = threading.Thread(target=receive, daemon=True)
    thread.start()
    return server.getsockname()[1], result, thread


@pytest.mark.parametrize('server_minimum,server_maximum,expected_version', [
    (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2, 'TLSv1.2'),
    (None, None, 'TLSv1.3'),
])
def test_tls_handshake_and_established_encrypted_send(
        client, server_minimum, server_maximum, expected_version):
    if expected_version == 'TLSv1.3' and not ssl.HAS_TLSv1_3:
        pytest.skip('当前 OpenSSL 不支持 TLS 1.3')
    application_payload = bytes.fromhex('01 02 03 04')
    port, received, thread = _start_tls_server(
        len(application_payload), server_minimum, server_maximum
    )

    handshake = client.post('/api/tcp/handshake', json={
        'target_ip': '127.0.0.1',
        'target_port': port,
        'mode': 'socket',
        'use_tls': True,
        'verify_tls': False,
    })
    body = handshake.get_json()
    assert body['success'] is True, body
    assert body['tls_enabled'] is True
    assert body['tls_version'] == expected_version
    assert body['cipher_suite']
    assert body['certificate_verified'] is False

    status = client.get(f"/api/tcp/status/{body['conn_id']}").get_json()
    assert status['tls_enabled'] is True
    assert status['tls_version'] == expected_version
    assert status['cipher_suite'] == body['cipher_suite']

    response = client.post('/api/tcp/attack', json={
        'conn_id': body['conn_id'],
        'packet_data': {'payload': application_payload.hex()},
        'count': 1,
        'interval': 0,
    })
    thread.join(timeout=6)

    assert response.get_json()['success'] is True, response.get_json()
    assert received['error'] is None
    assert received['version'] == expected_version
    assert received['data'] == application_payload
    assert received['data'] != bytes.fromhex('16 03 03 00 04 01 02 03 04')


def test_direct_tls_send_decrypts_to_application_payload(client):
    payload = b'bench-tls-application-data'
    port, received, thread = _start_tls_server(len(payload))
    response = client.post('/api/tcp/send', json={
        'target_ip': '127.0.0.1',
        'target_port': port,
        'packet_data': {'payload': 'ascii:' + payload.decode()},
        'use_tls': True,
        'verify_tls': False,
        'count': 1,
        'interval_ms': 0,
    })
    thread.join(timeout=6)

    body = response.get_json()
    assert body['success'] is True, body
    assert body['tls_enabled'] is True
    assert body['tls_version'] in ('TLSv1.2', 'TLSv1.3')
    assert body['cipher_suite']
    assert received['error'] is None
    assert received['data'] == payload


def test_tls_handshake_failure_never_falls_back_to_plain_tcp(client):
    port, received, thread = _start_plain_tcp_server()
    response = client.post('/api/tcp/handshake', json={
        'target_ip': '127.0.0.1',
        'target_port': port,
        'mode': 'socket',
        'use_tls': True,
    })
    thread.join(timeout=6)

    body = response.get_json()
    assert body['success'] is False
    assert body['conn_id'] is None
    assert body['state'] == 'TLS_HANDSHAKE_FAILED'
    assert '未回退普通 TCP' in body['message']
    assert received['error'] is None
    assert received['data'].startswith(b'\x16\x03')
    assert b'application-data' not in received['data']


def test_self_signed_certificate_is_rejected_when_verification_enabled(client):
    port, received, thread = _start_tls_server(1)
    response = client.post('/api/tcp/handshake', json={
        'target_ip': '127.0.0.1',
        'target_port': port,
        'mode': 'socket',
        'use_tls': True,
        'verify_tls': True,
    })
    thread.join(timeout=6)

    body = response.get_json()
    assert body['success'] is False
    assert body['state'] == 'TLS_HANDSHAKE_FAILED'
    assert 'CERTIFICATE_VERIFY_FAILED' in body['message']
    assert received['error'] is not None


def test_legacy_generic_sender_cannot_downgrade_tls_to_plain_tcp():
    manager = SendModeManager()
    with patch.object(manager, '_send_tcp_socket') as plain_tcp_send:
        result = manager.send(
            'TLS', 'socket', '127.0.0.1', 443, b'application-data'
        )
    assert result['success'] is False
    assert '禁止按普通 TCP 明文发送' in result['message']
    plain_tcp_send.assert_not_called()
