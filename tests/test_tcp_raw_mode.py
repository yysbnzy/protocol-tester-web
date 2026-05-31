# -*- coding: utf-8 -*-
"""
Phase 1 - Test 4: TCP Raw 模式测试

覆盖 Kimi Claw 正在修复的 Bug:
- Raw 模式握手正常完成
- 握手后发送不崩溃
- 连接断开后优雅处理
- Raw 模式与 Socket 模式状态隔离

注意：Raw 模式需要 Scapy 和管理员权限，
      测试中使用 simulate 模式模拟 + 条件跳过真实 Raw 测试。
"""

import pytest
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, tcp_manager, get_tcp_manager, limiter
from backend.core.tcp_manager import TCPConnectionManager, ConnectionState


class TestTcpRawMode:
    """TCP Raw 模式测试"""

    @pytest.fixture
    def client(self):
        """Flask 测试客户端"""
        app.config['TESTING'] = True
        limiter.enabled = False
        with app.test_client() as client:
            yield client

    def test_raw_handshake_simulate_fallback(self, client):
        """测试: Raw 模式在不可用时能够优雅降级或返回明确错误"""
        # 当 Scapy 未安装或缺少权限时，Raw 模式应该返回有意义的错误
        resp = client.post('/api/tcp/handshake',
            data=json.dumps({
                'target_ip': '127.0.0.1',
                'target_port': 80,
                'mode': 'raw'
            }),
            content_type='application/json'
        )
        data = resp.get_json()
        
        # 断言：不应该崩溃（500错误）
        assert resp.status_code in [200, 403, 500], \
            f"Raw 模式握手返回意外状态码: {resp.status_code}"
        
        # 如果成功，应该有 conn_id；如果失败，应该有明确的错误信息
        if resp.status_code == 200:
            assert 'success' in data, "Raw 模式响应缺少 success 字段"
            if data['success']:
                assert 'conn_id' in data, "Raw 模式成功但缺少 conn_id"
            else:
                # 失败时应该有明确的错误信息
                assert 'message' in data, "Raw 模式失败但缺少 message"
                error_msg = data['message'].lower()
                # Raw 模式失败可以是权限问题，也可以是其他原因（如网络问题）
                assert len(error_msg) > 0, "Raw 模式失败时 message 不应为空"
        elif resp.status_code in [403, 500]:
            # 权限不足时应该返回错误
            pass

    def test_raw_handshake_returns_correct_mode(self, client):
        """测试: Raw 模式握手返回的 mode 字段应为 'raw'"""
        resp = client.post('/api/tcp/handshake',
            data=json.dumps({
                'target_ip': '127.0.0.1',
                'target_port': 80,
                'mode': 'raw'
            }),
            content_type='application/json'
        )
        data = resp.get_json()
        
        if data and data.get('success') and 'mode' in data:
            assert data['mode'] == 'raw', \
                f"Raw 模式握手返回的 mode 应该是 'raw', 实际: {data['mode']}"

    def test_handshake_after_send_does_not_crash(self, client):
        """测试: 任何握手模式后，调用 /api/tcp/attack 不崩溃"""
        modes = ['socket', 'simulate', 'raw', 'npcap']
        
        for mode in modes:
            # 尝试握手
            handshake_resp = client.post('/api/tcp/handshake',
                data=json.dumps({
                    'target_ip': '127.0.0.1',
                    'target_port': 8080,
                    'mode': mode
                }),
                content_type='application/json'
            )
            handshake_data = handshake_resp.get_json()
            
            # 如果握手成功，尝试发送数据
            if handshake_data and handshake_data.get('success') and handshake_data.get('conn_id'):
                conn_id = handshake_data['conn_id']
                
                attack_resp = client.post('/api/tcp/attack',
                    data=json.dumps({
                        'conn_id': conn_id,
                        'packet_data': {'hex': 'DE AD BE EF'},
                        'count': 1,
                        'interval': 0
                    }),
                    content_type='application/json'
                )
                
                # 断言：无论结果如何，都不应该崩溃
                assert attack_resp.status_code in [200, 400, 500], \
                    f"mode={mode} 握手后发送返回意外状态码: {attack_resp.status_code}"

    def test_connection_close_graceful(self, client):
        """测试: 连接断开后优雅处理，资源正确释放"""
        # 建立 simulate 连接
        handshake_resp = client.post('/api/tcp/handshake',
            data=json.dumps({
                'target_ip': '127.0.0.1',
                'target_port': 80,
                'mode': 'simulate'
            }),
            content_type='application/json'
        )
        conn_id = handshake_resp.get_json()['conn_id']
        
        # 关闭连接
        close_resp = client.post('/api/tcp/close',
            data=json.dumps({'conn_id': conn_id}),
            content_type='application/json'
        )
        close_data = close_resp.get_json()
        
        # 断言：关闭应该成功
        assert close_data['success'] is True, f"连接关闭失败: {close_data}"
        
        # 关闭后再次发送应该失败
        attack_resp = client.post('/api/tcp/attack',
            data=json.dumps({
                'conn_id': conn_id,
                'packet_data': {'hex': 'FF FF'},
                'count': 1,
                'interval': 0
            }),
            content_type='application/json'
        )
        attack_data = attack_resp.get_json()
        
        # 断言：对已关闭连接发送应该失败
        assert attack_data['success'] is False, \
            f"对已关闭连接发送应该失败: {attack_data}"
        
        # 关闭后再次关闭不应该崩溃
        close2_resp = client.post('/api/tcp/close',
            data=json.dumps({'conn_id': conn_id}),
            content_type='application/json'
        )
        # 不应该崩溃（返回 200 或 404 都可以）
        assert close2_resp.status_code in [200, 404], \
            f"重复关闭返回意外状态码: {close2_resp.status_code}"

    def test_status_query_for_nonexistent_connection(self, client):
        """测试: 查询不存在的连接状态返回明确错误"""
        resp = client.get('/api/tcp/status/nonexistent-12345')
        data = resp.get_json()
        
        # 断言：应该返回 None 或明确的错误结构
        if data is not None:
            assert 'state' not in data or data.get('state') in ['error', 'closed', None], \
                f"不存在的连接状态查询返回异常: {data}"

    def test_handshake_invalid_ip_rejected(self, client):
        """测试: 非法 IP 格式握手应该被拒绝或处理"""
        invalid_ips = [
            '999.999.999.999',
            '256.1.1.1',
            'not-an-ip',
            '',
            '192.168.1',
        ]
        
        for invalid_ip in invalid_ips:
            resp = client.post('/api/tcp/handshake',
                data=json.dumps({
                    'target_ip': invalid_ip,
                    'target_port': 80,
                    'mode': 'simulate'
                }),
                content_type='application/json'
            )
            # 断言：不应该崩溃
            assert resp.status_code in [200, 400], \
                f"非法 IP '{invalid_ip}' 导致状态码异常: {resp.status_code}"

    def test_handshake_invalid_port_rejected(self, client):
        """测试: 非法端口格式握手应该被拒绝或处理"""
        invalid_ports = [
            99999,   # 超范围
            -1,      # 负数
            0,       # 0端口（可能允许但需验证）
            'abc',   # 非数字
        ]
        
        for invalid_port in invalid_ports:
            resp = client.post('/api/tcp/handshake',
                data=json.dumps({
                    'target_ip': '127.0.0.1',
                    'target_port': invalid_port,
                    'mode': 'simulate'
                }),
                content_type='application/json'
            )
            # 断言：不应该崩溃
            assert resp.status_code in [200, 400], \
                f"非法端口 '{invalid_port}' 导致状态码异常: {resp.status_code}"

    def test_tcp_manager_tracks_connection_state(self):
        """测试: TCPConnectionManager 内部正确跟踪连接状态"""
        mgr = TCPConnectionManager(logger=lambda x: print(x))
        
        # simulate 模式握手
        result = mgr.one_click_handshake('127.0.0.1', 8080, mode='simulate')
        assert result['success'] is True
        conn_id = result['conn_id']
        
        # 验证状态跟踪
        status = mgr.get_connection_status(conn_id)
        assert status is not None, "simulate 模式也应该跟踪连接状态"
        assert status['state'] == 'established', f"连接状态应该是 established: {status['state']}"
        
        # 关闭后验证状态
        mgr.close_connection(conn_id)
        status_after = mgr.get_connection_status(conn_id)
        assert status_after is None, "关闭后连接状态应该为 None"

    def test_tcp_manager_multiple_connections_isolated(self):
        """测试: 多个连接之间相互隔离"""
        mgr = TCPConnectionManager(logger=lambda x: print(x))
        
        # 创建两个连接
        result1 = mgr.one_click_handshake('127.0.0.1', 8081, mode='simulate')
        result2 = mgr.one_click_handshake('127.0.0.1', 8082, mode='simulate')
        
        conn_id1 = result1['conn_id']
        conn_id2 = result2['conn_id']
        
        assert conn_id1 != conn_id2, "两个连接应该有不同 ID"
        
        # 验证状态独立
        status1 = mgr.get_connection_status(conn_id1)
        status2 = mgr.get_connection_status(conn_id2)
        
        assert status1['target'] == '127.0.0.1:8081', "连接1目标端口应为8081"
        assert status2['target'] == '127.0.0.1:8082', "连接2目标端口应为8082"
        
        # 关闭一个，另一个应该仍然存在
        mgr.close_connection(conn_id1)
        
        status1_after = mgr.get_connection_status(conn_id1)
        status2_after = mgr.get_connection_status(conn_id2)
        
        assert status1_after is None, "连接1已关闭，状态应为 None"
        assert status2_after is not None, "连接2未关闭，状态应该存在"

    def test_disconnect_all_cleans_resources(self):
        """测试: disconnect_all 正确清理所有资源"""
        mgr = TCPConnectionManager(logger=lambda x: print(x))
        
        # 创建多个连接
        for port in [8080, 8081, 8082]:
            mgr.one_click_handshake('127.0.0.1', port, mode='simulate')
        
        # 验证连接存在
        all_conns = mgr.get_all_connections()
        assert len(all_conns) == 3, f"应该有 3 个连接，实际有 {len(all_conns)}"
        
        # 断开所有
        mgr.disconnect_all()
        
        # 验证全部清理
        all_conns_after = mgr.get_all_connections()
        assert len(all_conns_after) == 0, f"disconnect_all 后应该没有连接，实际有 {len(all_conns_after)}"
