# -*- coding: utf-8 -*-
"""ADB 临时监听准备与清理测试。"""

import subprocess
from unittest.mock import Mock, patch

from app import app, init_app, limiter
from backend.core.adb_listener import ADBListenerManager


init_app()


def _completed(returncode=0, stdout='', stderr=''):
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


def test_skip_when_adb_is_not_installed():
    manager = ADBListenerManager()
    with patch('backend.core.adb_listener.shutil.which', return_value=None):
        result = manager.ensure_listener('10.219.115.83', 80)
    assert result['skipped'] is True
    assert result['created'] is False
    assert '未检测到 adb' in result['events'][0]


def test_existing_listener_is_not_replaced():
    manager = ADBListenerManager()
    responses = [
        _completed(stdout='connected to 10.219.115.83:5555'),
        _completed(stdout='restarting adbd as root'),
        _completed(),
        _completed(stdout='uid=0(root) gid=0(root)'),
        _completed(returncode=0),
    ]
    with patch('backend.core.adb_listener.shutil.which', return_value='/usr/bin/adb'), \
         patch('backend.core.adb_listener.subprocess.run', side_effect=responses) as run:
        result = manager.ensure_listener('10.219.115.83', 80)
    assert result['success'] is True
    assert result['created'] is False
    assert run.call_count == 5
    assert run.call_args_list[-1].args[0][-1].startswith('if command -v ss')
    assert '已有 TCP 监听' in result['events'][-1]


def test_start_nc_listener_and_confirm_listen():
    manager = ADBListenerManager()
    responses = [
        _completed(stdout='already connected to 10.219.115.83:5555'),
        _completed(stdout='already running as root'),
        _completed(),
        _completed(stdout='uid=0(root) gid=0(root)'),
        _completed(returncode=1),
        _completed(stdout='4321\n'),
        _completed(returncode=0),
    ]
    with patch('backend.core.adb_listener.shutil.which', return_value='/usr/bin/adb'), \
         patch('backend.core.adb_listener.subprocess.run', side_effect=responses), \
         patch('backend.core.adb_listener.time.sleep'):
        result = manager.ensure_listener('10.219.115.83', 80)
    assert result['success'] is True
    assert result['created'] is True
    assert result['listener_pid'] == 4321
    assert result['serial'] == '10.219.115.83:5555'


def test_root_failure_does_not_start_listener():
    manager = ADBListenerManager()
    responses = [
        _completed(stdout='connected to 10.219.115.83:5555'),
        _completed(returncode=1, stderr='adbd cannot run as root in production builds'),
        _completed(returncode=1, stderr='su: inaccessible'),
        _completed(returncode=1, stderr='su: inaccessible'),
        _completed(returncode=1, stderr='su: inaccessible'),
    ]
    with patch('backend.core.adb_listener.shutil.which', return_value='/usr/bin/adb'), \
         patch('backend.core.adb_listener.subprocess.run', side_effect=responses) as run:
        result = manager.ensure_listener('10.219.115.83', 80)
    assert result['success'] is False
    assert result['created'] is False
    assert run.call_count == 5
    assert 'adb root/su 均不可用' in result['events'][-1]


def test_missing_nc_and_python_returns_failure():
    manager = ADBListenerManager()
    responses = [
        _completed(stdout='connected to 10.219.115.83:5555'),
        _completed(stdout='restarting adbd as root'),
        _completed(),
        _completed(stdout='uid=0(root) gid=0(root)'),
        _completed(returncode=1),
        _completed(returncode=127),
    ]
    with patch('backend.core.adb_listener.shutil.which', return_value='/usr/bin/adb'), \
         patch('backend.core.adb_listener.subprocess.run', side_effect=responses):
        result = manager.ensure_listener('10.219.115.83', 80)
    assert result['success'] is False
    assert result['created'] is False
    assert '临时监听启动失败' in result['events'][-1]


def test_cleanup_only_kills_created_listener():
    manager = ADBListenerManager()
    with patch('backend.core.adb_listener.shutil.which', return_value='/usr/bin/adb'), \
         patch.object(manager, '_shell', return_value=_completed()) as shell:
        cleaned = manager.cleanup_listener({
            'created': True,
            'serial': '10.219.115.83:5555',
            'listener_pid': 4321,
        })
        shell.assert_called_once()
        assert 'kill 4321' in shell.call_args.args[2]
    assert cleaned is True
    assert manager.cleanup_listener({'created': False}) is False


def test_failed_handshake_cleans_created_listener():
    app.config['TESTING'] = True
    limiter.enabled = False
    listener_info = {
        'success': True,
        'created': True,
        'listener_pid': 4321,
        'serial': '10.219.115.83:5555',
        'events': ['临时监听已就绪'],
    }
    with app.test_client() as client, \
         patch('routes.tcp_routes.adb_listener.prepare_for_handshake', return_value=listener_info), \
         patch('routes.tcp_routes.adb_listener.cleanup_listener') as cleanup, \
         patch('routes.tcp_routes.tcp_manager') as manager:
        manager.one_click_handshake.return_value = {
            'success': False, 'conn_id': None, 'message': '连接被拒绝'
        }
        response = client.post('/api/tcp/handshake', json={
            'target_ip': '10.219.115.83',
            'target_port': 80,
            'mode': 'socket',
        })
    body = response.get_json()
    assert body['success'] is False
    assert body['preparation'] == ['临时监听已就绪']
    cleanup.assert_called_once_with(listener_info)


def test_close_connection_cleans_created_listener():
    app.config['TESTING'] = True
    limiter.enabled = False
    listener_info = {
        'success': True,
        'created': True,
        'listener_pid': 4321,
        'serial': '10.219.115.83:5555',
        'events': ['临时监听已就绪'],
    }
    with app.test_client() as client, \
         patch('routes.tcp_routes.adb_listener.prepare_for_handshake', return_value=listener_info), \
         patch('routes.tcp_routes.adb_listener.cleanup_listener', return_value=True) as cleanup, \
         patch('routes.tcp_routes.tcp_manager') as manager:
        manager.connections = {'sock123': {}}
        manager.one_click_handshake.return_value = {
            'success': True,
            'conn_id': 'sock123',
            'message': '握手成功',
            'state': 'ESTABLISHED',
        }
        manager.close_connection.return_value = {
            'success': True,
            'message': '连接已关闭',
        }
        handshake = client.post('/api/tcp/handshake', json={
            'target_ip': '10.219.115.83',
            'target_port': 80,
            'mode': 'socket',
        })
        assert handshake.get_json()['success'] is True
        assert manager.connections['sock123']['adb_listener'] == listener_info

        closed = client.post('/api/tcp/close', json={'conn_id': 'sock123'})

    assert closed.get_json()['adb_listener_cleaned'] is True
    cleanup.assert_called_once_with(listener_info)


def test_repeated_ensure_preserves_owned_listener_identity():
    manager = ADBListenerManager()
    responses = [
        _completed(stdout='restarting adbd as root'),
        _completed(),
        _completed(stdout='uid=0(root) gid=0(root)'),
        _completed(returncode=1),
        _completed(stdout='4321\n'),
        _completed(returncode=0),
        _completed(stdout='already running as root'),
        _completed(),
        _completed(stdout='uid=0(root) gid=0(root)'),
        _completed(returncode=0),
    ]
    with patch('backend.core.adb_listener.shutil.which', return_value='/usr/bin/adb'), \
         patch('backend.core.adb_listener.subprocess.run', side_effect=responses), \
         patch('backend.core.adb_listener.time.sleep'):
        first = manager.ensure_listener(
            '192.168.3.4', 80,
            serial='192.168.3.4:44033', connection_type='wireless_pair',
        )
        second = manager.ensure_listener(
            '192.168.3.4', 80,
            serial='192.168.3.4:44033', connection_type='wireless_pair',
        )

    assert first['created'] is True
    assert second['created'] is True
    assert second['listener_pid'] == 4321
    assert second['target_port'] == 80
    assert manager._listener_info['listener_pid'] == 4321
    assert '复用本工具创建' in second['events'][-1]


def test_cleanup_command_rechecks_listen_state():
    manager = ADBListenerManager()
    with patch('backend.core.adb_listener.shutil.which', return_value='/usr/bin/adb'), \
         patch.object(manager, '_shell', return_value=_completed()) as shell:
        cleaned = manager.cleanup_listener({
            'created': True,
            'serial': '192.168.3.4:44033',
            'listener_pid': 4321,
            'target_port': 80,
            'use_root': True,
        })

    assert cleaned is True
    command = shell.call_args.args[2]
    assert 'kill 4321' in command
    assert 'ss -tln' in command
    assert 'if (' in command
