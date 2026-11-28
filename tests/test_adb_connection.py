# -*- coding: utf-8 -*-
"""ADB 动态设备发现、无线配对与高层交互测试。"""

import subprocess
from unittest.mock import patch

from app import app, init_app, limiter
from backend.core.adb_listener import ADBListenerManager


init_app()


def _completed(returncode=0, stdout='', stderr=''):
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


def test_discover_dynamic_wireless_and_pairing_ports():
    manager = ADBListenerManager()
    responses = [
        _completed(stdout=(
            'List of devices attached\n'
            'ABC123 device usb:1-1 product:car\n'
            '192.168.3.4:44033 device product:phone\n'
        )),
        _completed(stdout=(
            'List of discovered mdns services\n'
            'adb-phone _adb-tls-pairing._tcp. 192.168.3.4:37001\n'
            'adb-phone _adb-tls-connect._tcp. 192.168.3.4:44033\n'
        )),
    ]
    with patch('backend.core.adb_listener.shutil.which', return_value='/usr/bin/adb'), \
         patch('backend.core.adb_listener.subprocess.run', side_effect=responses):
        result = manager.list_devices()

    assert result['devices'][0]['connection_type'] == 'wired'
    assert result['devices'][1]['serial'] == '192.168.3.4:44033'
    assert result['pairable'][0]['port'] == 37001
    assert result['connectable'][0]['port'] == 44033


def test_pair_then_auto_discover_connection_port():
    manager = ADBListenerManager()
    responses = [
        _completed(stdout='Successfully paired to 192.168.3.4:37001'),
        _completed(stdout='List of devices attached\n'),
        _completed(stdout='adb-phone _adb-tls-connect._tcp. 192.168.3.4:44033\n'),
        _completed(stdout='connected to 192.168.3.4:44033'),
    ]
    with patch('backend.core.adb_listener.shutil.which', return_value='/usr/bin/adb'), \
         patch('backend.core.adb_listener.subprocess.run', side_effect=responses) as run:
        result = manager.connect_device(
            'pair', '192.168.3.4', pair_port=37001, pair_code='123456'
        )

    assert result['success'] is True
    assert result['serial'] == '192.168.3.4:44033'
    assert result['status']['connection_type'] == 'wireless_pair'
    assert run.call_args_list[-1].args[0][-2:] == ['connect', '192.168.3.4:44033']


def test_high_port_can_listen_without_root():
    manager = ADBListenerManager()
    responses = [
        _completed(returncode=1, stderr='su: inaccessible'),
        _completed(returncode=1),
        _completed(stdout='4567\n'),
        _completed(returncode=0),
    ]
    with patch('backend.core.adb_listener.shutil.which', return_value='/usr/bin/adb'), \
         patch('backend.core.adb_listener.subprocess.run', side_effect=responses), \
         patch('backend.core.adb_listener.time.sleep'):
        result = manager.ensure_listener(
            '192.168.3.4', 8080,
            serial='192.168.3.4:44033', connection_type='wireless_pair'
        )

    assert result['success'] is True
    assert result['use_root'] is False
    assert result['status']['listener_active'] is True
    assert result['status']['adb_port'] == 44033


def test_adb_connect_api_runs_listener_after_connection():
    app.config['TESTING'] = True
    limiter.enabled = False
    status = {
        'connected': True, 'serial': '192.168.3.4:44033',
        'connection_type': 'wireless_pair', 'target_ip': '192.168.3.4',
        'adb_port': 44033, 'listener_active': True, 'listener_port': 8080,
    }
    with app.test_client() as client, \
         patch('routes.adb_routes.adb_listener.connect_device', return_value={
             'success': True, 'events': ['ADB 已连接'],
             'serial': '192.168.3.4:44033', 'status': status,
         }), \
         patch('routes.adb_routes.adb_listener.ensure_listener', return_value={
             'success': True, 'events': ['监听成功'], 'status': status,
         }) as listener:
        response = client.post('/api/adb/connect', json={
            'method': 'pair', 'target_ip': '192.168.3.4', 'target_port': 8080,
            'pair_port': 37001, 'pair_code': '123456',
        })

    assert response.get_json()['success'] is True
    assert response.get_json()['status'] == status
    assert listener.call_args.kwargs['serial'] == '192.168.3.4:44033'


def test_pair_recovery_with_connect_port_skips_repeated_pair():
    manager = ADBListenerManager()
    with patch('backend.core.adb_listener.shutil.which', return_value='/usr/bin/adb'), \
         patch('backend.core.adb_listener.subprocess.run',
               return_value=_completed(stdout='connected to 192.168.3.4:44033')) as run:
        result = manager.connect_device(
            'pair', '192.168.3.4', connect_port=44033,
        )

    assert result['success'] is True
    assert run.call_count == 1
    assert run.call_args.args[0][-2:] == ['connect', '192.168.3.4:44033']
    assert '跳过重复配对' in result['events'][0]
