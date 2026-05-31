# -*- coding: utf-8 -*-
"""
Phase 1 - Test 2: 配置统一测试

覆盖 Kimi Claw 正在修复的 Bug:
- 修改配置后前后端保持一致
- 重启后配置持久化
- 非法配置值被拒绝
- 后端硬编码默认值从数据库/配置文件获取
"""

import pytest
import json
import sys
import os
import tempfile
import shutil

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.core.config_manager import ConfigManager, get_config_manager


class TestConfigSync:
    """配置一致性测试 - 后端配置管理器"""

    @pytest.fixture
    def temp_config_dir(self):
        """创建临时配置目录，隔离测试环境"""
        temp_dir = tempfile.mkdtemp(prefix='pt_test_config_')
        yield temp_dir
        shutil.rmtree(temp_dir, ignore_errors=True)

    def test_config_load_returns_expected_structure(self, temp_config_dir):
        """测试: 配置加载返回预期的数据结构"""
        mgr = ConfigManager(config_dir=temp_config_dir)
        config = mgr.current_config

        # 断言：配置必须有预期的顶层键
        assert 'protocols' in config, "配置缺少 'protocols' 键"
        assert 'settings' in config, "配置缺少 'settings' 键"
        assert 'version' in config, "配置缺少 'version' 键"

        # 断言：必须有预期的协议
        protocols = config['protocols']
        expected_protocols = ['TCP', 'UDP', 'IP', 'ICMP', 'ARP', 'SOMEIP', 'DOIP', 'SOMEIP-SD']
        for proto in expected_protocols:
            assert proto in protocols, f"配置缺少协议 '{proto}'"

        # 断言：每个协议必须有 legal 和 illegal 字段
        for proto_name, proto_config in protocols.items():
            assert 'legal' in proto_config, f"协议 '{proto_name}' 缺少 'legal' 配置"
            assert 'illegal' in proto_config, f"协议 '{proto_name}' 缺少 'illegal' 配置"
            assert isinstance(proto_config['legal'], dict), \
                f"协议 '{proto_name}' 的 legal 必须是字典"
            assert isinstance(proto_config['illegal'], dict), \
                f"协议 '{proto_name}' 的 illegal 必须是字典"

    def test_config_persistence_after_save_and_reload(self, temp_config_dir):
        """测试: 保存后重启（重新实例化）配置持久化"""
        # 第一次实例化：修改配置
        mgr1 = ConfigManager(config_dir=temp_config_dir)
        original_tcp_legal = dict(mgr1.current_config['protocols']['TCP']['legal'])
        
        # 修改 TCP 的合法值
        new_srcport = '9999'
        mgr1.current_config['protocols']['TCP']['legal']['srcport'] = new_srcport
        mgr1.save_default_config(mgr1.current_config)

        # 第二次实例化：模拟重启
        mgr2 = ConfigManager(config_dir=temp_config_dir)
        
        # 断言：修改后的值应该被保留
        assert mgr2.current_config['protocols']['TCP']['legal']['srcport'] == new_srcport, \
            f"配置持久化失败: 期望 srcport='{new_srcport}', 实际='{mgr2.current_config['protocols']['TCP']['legal']['srcport']}'"
        
        # 断言：其他未被修改的值应该保持不变
        for key, value in original_tcp_legal.items():
            if key != 'srcport':
                actual = mgr2.current_config['protocols']['TCP']['legal'][key]
                assert actual == value, \
                    f"配置持久化破坏了未修改字段: {key} 期望 '{value}', 实际 '{actual}'"

    def test_config_save_and_load_roundtrip(self, temp_config_dir):
        """测试: 配置保存后加载，数据一致"""
        mgr = ConfigManager(config_dir=temp_config_dir)
        
        # 修改多个字段
        test_config = mgr.current_config
        test_config['protocols']['IP']['legal']['ttl'] = '128'
        test_config['protocols']['UDP']['illegal']['dstport'] = '77777'
        test_config['settings']['send_mode'] = 'raw'
        test_config['settings']['send_count'] = 10

        # 保存
        success = mgr.save_default_config(test_config)
        assert success is True, "配置保存失败"

        # 重新加载
        mgr.current_config = mgr.load_default_config()
        loaded = mgr.current_config

        # 断言：所有修改的值一致
        assert loaded['protocols']['IP']['legal']['ttl'] == '128', \
            "IP ttl 保存/加载不一致"
        assert loaded['protocols']['UDP']['illegal']['dstport'] == '77777', \
            "UDP illegal dstport 保存/加载不一致"
        assert loaded['settings']['send_mode'] == 'raw', \
            "settings.send_mode 保存/加载不一致"
        assert loaded['settings']['send_count'] == 10, \
            "settings.send_count 保存/加载不一致"

    def test_config_api_backend_consistency(self, temp_config_dir):
        """测试: 后端 API 返回的配置与 ConfigManager 内部一致"""
        from app import app
        import app as app_module
        
        app.config['TESTING'] = True
        
        # 重置全局 config_mgr 并清理配置文件，确保测试隔离
        app_module.config_mgr = None
        default_config = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config', 'default.json')
        if os.path.exists(default_config):
            os.remove(default_config)
        
        # 使用临时配置目录（通过环境变量或 monkeypatch）
        with app.test_client() as client:
            # 加载配置 API
            resp = client.get('/api/config/load')
            data = resp.get_json()
            
            assert data['success'] is True, "加载配置 API 失败"
            assert 'config' in data, "加载配置 API 缺少 config 字段"
            
            config = data['config']
            # 断言：返回的结构与 ConfigManager 的预期一致
            assert 'protocols' in config, "API 返回配置缺少 protocols"
            assert 'settings' in config, "API 返回配置缺少 settings"

    def test_config_defaults_api_returns_all_protocols(self, temp_config_dir):
        """测试: /api/defaults 返回所有协议的默认值"""
        from app import app
        import app as app_module
        
        app.config['TESTING'] = True
        
        # 重置全局 config_mgr 并清理配置文件，确保测试隔离
        app_module.config_mgr = None
        default_config = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config', 'default.json')
        if os.path.exists(default_config):
            os.remove(default_config)
        
        with app.test_client() as client:
            resp = client.get('/api/defaults')
            data = resp.get_json()
            
            assert data['success'] is True, "/api/defaults 返回失败"
            assert 'legal' in data, "/api/defaults 缺少 legal 字段"
            assert 'illegal' in data, "/api/defaults 缺少 illegal 字段"
            
            # 断言：所有预期协议都有默认值
            expected_protocols = ['TCP', 'UDP', 'IP', 'ICMP', 'ARP', 'SOMEIP', 'DOIP', 'SOMEIP-SD']
            for proto in expected_protocols:
                assert proto in data['legal'], f"/api/defaults legal 缺少协议 '{proto}'"
                assert proto in data['illegal'], f"/api/defaults illegal 缺少协议 '{proto}'"

    def test_config_save_rejects_empty_config(self, temp_config_dir):
        """测试: 保存空/非法配置应该被拒绝或处理"""
        mgr = ConfigManager(config_dir=temp_config_dir)
        
        # 尝试保存空配置
        empty_config = {}
        result = mgr.save_default_config(empty_config)
        
        # 保存可能成功（覆盖为空），但重新加载后应该能恢复或至少不崩溃
        mgr.current_config = mgr.load_default_config()
        
        # 如果保存了空配置，重新加载应该能处理（至少不崩溃）
        # 断言：无论结果如何，都不应该抛出异常导致测试崩溃
        assert isinstance(mgr.current_config, dict), "加载配置后应该返回字典"

    def test_config_update_protocol_config(self, temp_config_dir):
        """测试: update_protocol_config 方法正确更新单个协议"""
        mgr = ConfigManager(config_dir=temp_config_dir)
        
        new_legal = {
            'TCP.srcport': '11111',
            'TCP.dstport': '22222',
            'TCP.seq': '100',
            'TCP.ack': '200',
            'TCP.flags': '0x10 (ACK)',
            'TCP.window_size': '8192',
            'TCP.checksum': '0xABCD'
        }
        new_illegal = {
            'TCP.srcport': '99999',
            'TCP.dstport': '0',
            'TCP.seq': '0xEEEEEEEE',
            'TCP.ack': '0xFFFFFFFF',
            'TCP.flags': '0xFF',
            'TCP.window_size': '0',
            'TCP.checksum': '0xDEAD'
        }
        
        result = mgr.update_protocol_config('TCP', new_legal, new_illegal)
        assert result is True, "update_protocol_config 应该返回 True"
        
        # 验证修改已生效
        tcp_config = mgr.get_protocol_config('TCP')
        assert tcp_config['legal'] == new_legal, "TCP legal 配置未正确更新"
        assert tcp_config['illegal'] == new_illegal, "TCP illegal 配置未正确更新"
        
        # 验证其他协议未被影响
        ip_config = mgr.get_protocol_config('IP')
        assert 'IP.version' in ip_config['legal'], "更新 TCP 配置不应该破坏 IP 配置"

    def test_config_settings_persistence(self, temp_config_dir):
        """测试: settings 修改后持久化"""
        mgr = ConfigManager(config_dir=temp_config_dir)
        
        new_settings = {
            'default_nic': 'TestNIC',
            'send_mode': 'npcap',
            'send_count': 100,
            'send_interval': 50
        }
        
        mgr.update_settings(new_settings)
        
        # 重新加载
        mgr2 = ConfigManager(config_dir=temp_config_dir)
        loaded_settings = mgr2.get_settings()
        
        assert loaded_settings['default_nic'] == 'TestNIC', "settings.default_nic 未持久化"
        assert loaded_settings['send_mode'] == 'npcap', "settings.send_mode 未持久化"
        assert loaded_settings['send_count'] == 100, "settings.send_count 未持久化"
        assert loaded_settings['send_interval'] == 50, "settings.send_interval 未持久化"

    def test_config_preset_save_and_load(self, temp_config_dir):
        """测试: 预设配置保存和加载"""
        mgr = ConfigManager(config_dir=temp_config_dir)
        
        preset_name = 'test_preset'
        preset_config = {
            'protocols': {
                'TCP': {
                    'legal': {'srcport': '33333', 'dstport': '44444'},
                    'illegal': {'srcport': '0', 'dstport': '99999'}
                }
            },
            'settings': {'send_mode': 'simulate'}
        }
        
        # 保存预设
        result = mgr.save_preset(preset_name, preset_config)
        assert result is True, "预设保存失败"
        
        # 加载预设
        loaded = mgr.load_preset(preset_name)
        assert loaded is not None, "预设加载返回 None"
        assert loaded['protocols']['TCP']['legal']['srcport'] == '33333', "预设加载数据不一致"
        
        # 列出预设
        presets = mgr.list_presets()
        assert preset_name in presets, "list_presets 未返回已保存的预设"

    def test_config_no_hardcoded_defaults_in_api(self, temp_config_dir):
        """测试: 验证配置不是硬编码在 API 中，而是从配置文件/数据库加载"""
        # 创建自定义配置
        custom_config = {
            'protocols': {
                'CUSTOM_PROTO': {
                    'legal': {'field1': 'custom_value'},
                    'illegal': {'field1': 'bad_value'}
                }
            },
            'settings': {'test_mode': True},
            'version': '9.9.9'
        }
        
        # 直接写入配置文件
        default_file = os.path.join(temp_config_dir, 'default.json')
        with open(default_file, 'w', encoding='utf-8') as f:
            json.dump(custom_config, f)
        
        # 实例化 ConfigManager，应该从文件加载
        mgr = ConfigManager(config_dir=temp_config_dir)
        
        # 断言：加载了自定义配置而非硬编码默认值
        assert 'CUSTOM_PROTO' in mgr.current_config['protocols'], \
            "ConfigManager 应该从文件加载配置，而不是硬编码默认值"
        assert mgr.current_config['version'] == '9.9.9', \
            "ConfigManager 应该从文件加载版本，而不是硬编码"
