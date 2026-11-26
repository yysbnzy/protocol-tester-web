# -*- coding: utf-8 -*-
"""浏览器验证 TCP Socket 请求携带共享 Payload。"""

import json


TLS_TEXT = '16 03 01 00 02 01 00'


def _open_tcp_socket(page, app_url):
    page.goto(app_url)
    page.wait_for_function(
        "typeof sendPacket === 'function' && typeof buildPacketData === 'function'"
    )
    page.locator('[data-testid="send-mode-select"]').select_option('socket')
    page.locator('[data-testid="protocol-btn-TCP"]').click()
    page.locator('#legal-Payload-payload').wait_for()
    page.locator('#legal-Payload-payload').fill(TLS_TEXT)


def test_direct_socket_request_contains_shared_payload(page, app_url):
    _open_tcp_socket(page, app_url)
    page.route('**/api/tcp/send', lambda route: route.fulfill(
        status=200,
        content_type='application/json',
        body=json.dumps({'success': True, 'total_sent': 7}),
    ))

    with page.expect_request('**/api/tcp/send', timeout=10000) as request_info:
        page.locator('[data-testid="send-btn"]').click()

    body = request_info.value.post_data_json
    assert body['mode'] == 'socket'
    assert body['packet_data']['payload'] == TLS_TEXT


def test_established_socket_request_contains_shared_payload(page, app_url):
    _open_tcp_socket(page, app_url)
    page.route('**/api/tcp/handshake', lambda route: route.fulfill(
        status=200,
        content_type='application/json',
        body=json.dumps({
            'success': True,
            'conn_id': 'socket01',
            'state': 'ESTABLISHED',
        }),
    ))
    page.route('**/api/tcp/attack', lambda route: route.fulfill(
        status=200,
        content_type='application/json',
        body=json.dumps({'success': True, 'connection_alive': True}),
    ))

    with page.expect_response('**/api/tcp/handshake', timeout=10000):
        page.locator('[data-testid="handshake-btn"]').click()
    page.wait_for_function('tcpConnId === "socket01"')

    with page.expect_request('**/api/tcp/attack', timeout=10000) as request_info:
        page.locator('[data-testid="send-btn"]').click()

    body = request_info.value.post_data_json
    assert body['conn_id'] == 'socket01'
    assert body['packet_data']['payload'] == TLS_TEXT


def test_raw_mode_still_uses_multi_protocol_builder(page, app_url):
    _open_tcp_socket(page, app_url)
    page.locator('[data-testid="send-mode-select"]').select_option('raw')
    page.route('**/api/scapy/build-multi', lambda route: route.fulfill(
        status=200,
        content_type='application/json',
        body=json.dumps({'success': True, 'packet_hex': '00', 'packet_bytes': [0]}),
    ))
    page.route('**/api/scapy/send', lambda route: route.fulfill(
        status=200,
        content_type='application/json',
        body=json.dumps({'success': True}),
    ))

    with page.expect_request('**/api/scapy/build-multi', timeout=10000) as request_info:
        page.locator('[data-testid="send-btn"]').click()

    body = request_info.value.post_data_json
    assert body['protocols'] == ['ARP', 'TCP', 'IP']
    assert body['fields']['TCP']['payload'] == TLS_TEXT
