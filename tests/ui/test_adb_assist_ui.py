# -*- coding: utf-8 -*-
"""ADB 辅助监听面板、配对和两秒结果弹窗浏览器测试。"""

import json


CONNECTED_STATUS = {
    'connected': True,
    'serial': '192.168.3.4:44033',
    'connection_type': 'wireless_pair',
    'target_ip': '192.168.3.4',
    'adb_port': 44033,
    'listener_active': True,
    'listener_port': 8080,
}


def _json(route, body):
    route.fulfill(status=200, content_type='application/json', body=json.dumps(body))


def _open_adb(page, app_url):
    page.route('**/api/adb/status', lambda route: _json(route, {
        'success': True, 'adb_available': True, 'status': {},
    }))
    page.route('**/api/adb/devices', lambda route: _json(route, {
        'success': True,
        'adb_available': True,
        'devices': [
            {'serial': 'USB001', 'state': 'device', 'connection_type': 'wired'},
        ],
        'pairable': [
            {'name': 'phone', 'target_ip': '192.168.3.4', 'port': 37001},
        ],
        'connectable': [
            {'name': 'phone', 'target_ip': '192.168.3.4', 'port': 44033},
        ],
        'status': {},
    }))
    page.goto(app_url)
    page.wait_for_function("typeof submitAdbConnection === 'function'")
    page.locator('[data-testid="target-ip"]').fill('192.168.3.4')
    page.locator('[data-testid="target-port"]').fill('8080')
    page.locator('[data-testid="adb-connection-btn"]').click()
    page.locator('#adbWiredDevice option[value="USB001"]').wait_for(state='attached')


def test_adb_panel_above_lowered_log_and_all_status_fields(page, app_url):
    _open_adb(page, app_url)
    page.locator('#adbConnectionModal .modal-close').click()
    page.evaluate("status => updateAdbStatus(status)", CONNECTED_STATUS)

    assert page.locator('[data-testid="adb-connection-btn"]').inner_text() == 'ADB已连接'
    assert page.locator('[data-testid="adb-method-text"]').inner_text() == '无线配对连接'
    assert page.locator('[data-testid="adb-target-text"]').inner_text() == '192.168.3.4:44033'
    assert page.locator('text=监听中（8080）').is_visible()
    adb_box = page.locator('.adb-assist-panel').bounding_box()
    log_box = page.locator('.adb-log-panel').bounding_box()
    assert log_box['y'] > adb_box['y'] + adb_box['height']


def test_pairable_device_automatically_fills_pair_and_connect_ports(page, app_url):
    _open_adb(page, app_url)
    page.locator('[data-testid="adb-method-pair"]').click()
    assert page.locator('[data-testid="adb-pair-ip"]').input_value() == '192.168.3.4'
    assert page.locator('[data-testid="adb-pair-port"]').input_value() == '37001'
    assert page.locator('[data-testid="adb-connect-port"]').input_value() == '44033'


def test_success_closes_result_and_connection_dialogs_after_two_seconds(page, app_url):
    _open_adb(page, app_url)
    page.route('**/api/adb/connect', lambda route: _json(route, {
        'success': True,
        'stage': 'ready',
        'message': 'ADB 连接及监听成功',
        'events': ['有线 ADB 已连接：USB001', '监听成功'],
        'status': CONNECTED_STATUS,
    }))

    with page.expect_request('**/api/adb/connect') as request_info:
        page.locator('[data-testid="adb-connect-submit"]').click()
    assert request_info.value.post_data_json['method'] == 'wired'
    assert request_info.value.post_data_json['target_port'] == 8080
    page.locator('#adbResultModal').wait_for(state='visible')
    page.wait_for_timeout(2200)
    assert not page.locator('#adbResultModal').is_visible()
    assert not page.locator('#adbConnectionModal').is_visible()
    assert page.locator('[data-testid="adb-connection-btn"]').inner_text() == 'ADB已连接'


def test_failure_closes_only_result_and_keeps_connection_dialog(page, app_url):
    _open_adb(page, app_url)
    page.locator('[data-testid="adb-method-wireless"]').click()
    page.route('**/api/adb/connect', lambda route: _json(route, {
        'success': False,
        'stage': 'connect',
        'message': 'ADB 连接未成功：failed to connect',
        'events': ['ADB 连接未成功：failed to connect'],
        'status': {},
    }))

    page.locator('[data-testid="adb-connect-submit"]').click()
    page.locator('#adbResultModal').wait_for(state='visible')
    page.wait_for_timeout(2200)
    assert not page.locator('#adbResultModal').is_visible()
    assert page.locator('#adbConnectionModal').is_visible()
    assert page.locator('[data-testid="adb-wireless-ip"]').input_value() == '192.168.3.4'
