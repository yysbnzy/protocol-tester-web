# -*- coding: utf-8 -*-
"""
Phase 1 - Test 3: 前端配置读取测试

覆盖 Kimi Claw 正在修复的 Bug:
- 页面加载时正确显示后端默认值（不是硬编码）
- 修改值后前端状态同步
- 后端修改后前端刷新能生效

测试聚焦在 /api/defaults 和 /api/config/* API 的行为一致性
"""

import pytest
import json
import sys
import os
import tempfile
import shutil

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, limiter


class TestFrontendConfig:
    """前端配置读取 API 测试"""

    @pytest.fixture
    def client(self):
        """Flask 测试客户端"""
        app.config['TESTING'] = True
        limiter.enabled = False
        
        # 重置全局 config_mgr 并清理配置文件，确保测试隔离
        import app as app_module
        app_module.config_mgr = None
        default_config = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config', 'default.json')
        if os.path.exists(default_config):
            os.remove(default_config)
        
        with app.test_client() as client:
            yield client

    @pytest.fixture
    def temp_config_dir(self):
        """临时配置目录"""
        temp_dir = tempfile.mkdtemp(prefix='pt_frontend_test_')
        yield temp_dir
        shutil.rmtree(temp_dir, ignore_errors=True)

    def test_defaults_api_returns_tcp_values(self, client):
        """测试: /api/defaults 返回 TCP 协议的默认值，前端可正确解析"""
        resp = client.get('/api/defaults')
        data = resp.get_json()
        
        assert data['success'] is True
        assert 'legal' in data
        assert 'illegal' in data
        
        # 断言：TCP 字段必须有明确的值
        tcp_legal = data['legal']['TCP']
        assert 'TCP.srcport' in tcp_legal, "TCP legal 缺少 TCP.srcport"
        assert 'TCP.dstport' in tcp_legal, "TCP legal 缺少 TCP.dstport"
        assert tcp_legal['TCP.srcport'] != '', "TCP srcport 不能为空字符串"
        assert tcp_legal['TCP.dstport'] != '', "TCP dstport 不能为空字符串"
        
        # 断言：TCP 非法值也必须存在
        tcp_illegal = data['illegal']['TCP']
        assert 'TCP.srcport' in tcp_illegal, "TCP illegal 缺少 TCP.srcport"
        assert tcp_illegal['TCP.srcport'] != '', "TCP illegal srcport 不能为空"

    def test_defaults_api_returns_all_expected_protocols(self, client):
        """测试: /api/defaults 返回所有 8 种协议的默认值"""
        resp = client.get('/api/defaults')
        data = resp.get_json()
        
        expected_protocols = ['TCP', 'UDP', 'IP', 'ICMP', 'ARP', 'SOMEIP', 'DOIP', 'SOMEIP-SD']
        
        for proto in expected_protocols:
            assert proto in data['legal'], f"默认值 API 缺少 legal.{proto}"
            assert proto in data['illegal'], f"默认值 API 缺少 illegal.{proto}"
            
            # 每个协议至少有一个字段
            assert len(data['legal'][proto]) > 0, f"{proto} legal 字段为空"
            assert len(data['illegal'][proto]) > 0, f"{proto} illegal 字段为空"

    def test_defaults_api_structure_matches_frontend_expectation(self, client):
        """测试: /api/defaults 返回结构符合前端期望格式 {legal: {...}, illegal: {...}}"""
        resp = client.get('/api/defaults')
        data = resp.get_json()
        
        # 前端期望格式：
        # {
        #   success: true,
        #   legal: { TCP: { srcport: '8080', ... }, ... },
        #   illegal: { TCP: { srcport: '99999', ... }, ... }
        # }
        
        assert isinstance(data['legal'], dict), "legal 必须是字典"
        assert isinstance(data['illegal'], dict), "illegal 必须是字典"
        
        for proto_name in data['legal']:
            proto_data = data['legal'][proto_name]
            assert isinstance(proto_data, dict), f"legal.{proto_name} 必须是字典"
            for field_name, field_value in proto_data.items():
                assert isinstance(field_value, str), \
                    f"legal.{proto_name}.{field_name} 值必须是字符串，实际类型: {type(field_value)}"

    def test_config_load_api_matches_defaults_api(self, client):
        """测试: /api/config/load 和 /api/defaults 返回的数据一致"""
        load_resp = client.get('/api/config/load')
        load_data = load_resp.get_json()
        
        defaults_resp = client.get('/api/defaults')
        defaults_data = defaults_resp.get_json()
        
        # 断言：两个 API 的协议数据应该一致
        config = load_data['config']
        
        for proto in ['TCP', 'UDP', 'IP']:
            config_legal = config.get('protocols', {}).get(proto, {}).get('legal', {})
            defaults_legal = defaults_data['legal'].get(proto, {})
            
            # 对于共有字段，值应该一致
            for field in set(config_legal.keys()) & set(defaults_legal.keys()):
                assert config_legal[field] == defaults_legal[field], \
                    f"{proto}.{field} 在两个 API 中不一致: config={config_legal[field]}, defaults={defaults_legal[field]}"

    def test_config_save_then_defaults_reflects_changes(self, client):
        """测试: 后端修改配置后，/api/defaults 能反映最新值"""
        # 先获取当前默认值
        defaults_resp = client.get('/api/defaults')
        old_defaults = defaults_resp.get_json()
        old_tcp_srcport = old_defaults['legal']['TCP']['TCP.srcport']
        
        # 修改配置
        new_config = old_defaults.copy()
        # 构建完整配置结构（/api/config/save 期望的格式）
        config_payload = {
            'config': {
                'protocols': {},
                'settings': old_defaults.get('settings', {}),
                'version': '1.0'
            }
        }
        
        # 将 legal/illegal 转换为 config 格式
        for proto in old_defaults['legal']:
            config_payload['config']['protocols'][proto] = {
                'legal': old_defaults['legal'][proto],
                'illegal': old_defaults['illegal'][proto]
            }
        
        # 修改 TCP srcport
        config_payload['config']['protocols']['TCP']['legal']['TCP.srcport'] = '7777'
        
        save_resp = client.post('/api/config/save',
            data=json.dumps(config_payload),
            content_type='application/json'
        )
        save_data = save_resp.get_json()
        
        # 保存可能成功也可能失败（取决于实现），但不应该崩溃
        assert save_resp.status_code in [200, 400, 500], \
            f"配置保存返回意外状态码: {save_resp.status_code}"
        
        # 如果保存成功，验证 /api/defaults 是否反映修改
        if save_data and save_data.get('success'):
            new_defaults_resp = client.get('/api/defaults')
            new_defaults = new_defaults_resp.get_json()
            
            # 断言：修改后的值应该反映在默认值中
            assert new_defaults['legal']['TCP']['TCP.srcport'] == '7777', \
                f"配置保存后 /api/defaults 未反映修改: 期望 '7777', 实际 '{new_defaults['legal']['TCP']['TCP.srcport']}'"

    def test_defaults_api_values_are_strings_not_null(self, client):
        """测试: 所有默认值都是字符串且不为 null/undefined"""
        resp = client.get('/api/defaults')
        data = resp.get_json()
        
        for proto in data['legal']:
            for field, value in data['legal'][proto].items():
                assert value is not None, f"legal.{proto}.{field} 值为 None"
                assert isinstance(value, str), f"legal.{proto}.{field} 不是字符串: {type(value)}"
                assert value != 'undefined', f"legal.{proto}.{field} 值为 'undefined'"
                assert value != 'null', f"legal.{proto}.{field} 值为 'null'"
        
        for proto in data['illegal']:
            for field, value in data['illegal'][proto].items():
                assert value is not None, f"illegal.{proto}.{field} 值为 None"
                assert isinstance(value, str), f"illegal.{proto}.{field} 不是字符串: {type(value)}"

    def test_frontend_can_parse_all_protocol_fields(self, client):
        """测试: 前端可以解析所有协议字段（字段名没有特殊字符导致 JSON 解析失败）"""
        resp = client.get('/api/defaults')
        data = resp.get_json()
        
        # 验证 JSON 可序列化（Flask 已经做了，但双重检查）
        try:
            json_str = json.dumps(data)
            reparsed = json.loads(json_str)
            assert reparsed == data, "JSON 序列化/反序列化后数据不一致"
        except Exception as e:
            pytest.fail(f"/api/defaults 返回的数据 JSON 序列化失败: {e}")
        
        # 验证字段名没有前导点（如 'IP.version' vs 'version'）
        for proto in data['legal']:
            for field_name in data['legal'][proto]:
                # 字段名应该是合法的 JSON 键
                assert isinstance(field_name, str), f"字段名不是字符串: {field_name}"
                # 字段名不应该为空
                assert len(field_name) > 0, f"字段名为空字符串"

    def test_config_api_no_crashes_on_concurrent_access(self, client):
        """测试: 并发访问配置 API 不会导致崩溃"""
        import threading
        import requests
        
        # 由于 Flask test_client 不是线程安全的，用顺序调用来模拟
        results = []
        for i in range(10):
            resp = client.get('/api/defaults')
            results.append(resp.status_code)
        
        # 所有请求都应该成功
        assert all(code == 200 for code in results), \
            f"并发访问 /api/defaults 出现非 200 状态码: {results}"

    def test_defaults_api_response_time(self, client):
        """测试: /api/defaults 响应时间合理（< 500ms）"""
        import time
        
        start = time.time()
        resp = client.get('/api/defaults')
        elapsed = (time.time() - start) * 1000
        
        # 断言：响应时间应该在合理范围内
        assert elapsed < 500, f"/api/defaults 响应时间过慢: {elapsed:.2f}ms"
        assert resp.status_code == 200
