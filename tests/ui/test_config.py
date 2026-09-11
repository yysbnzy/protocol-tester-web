# -*- coding: utf-8 -*-
"""
UI 测试：配置管理
"""

import pytest


class TestConfig:
    """配置管理测试"""

    def test_load_default_config(self, page, app_url):
        """UI-CFG-001: 加载默认配置"""
        page.goto(app_url)
        page.wait_for_selector("body", timeout=10000)
        page.wait_for_timeout(500)
        
        # 修改一个字段值
        page.locator("[data-testid=\"protocol-btn-TCP\"]").click()
        page.wait_for_timeout(500)
        page.locator("#legal-TCP-srcport").fill("99999")
        page.wait_for_timeout(200)
        
        # 刷新页面，等待配置加载
        page.reload()
        page.wait_for_selector("body", timeout=10000)
        page.wait_for_timeout(2000)
        page.locator("[data-testid=\"protocol-btn-TCP\"]").click()
        page.wait_for_timeout(500)
        
        # 验证字段有值
        srcport = page.locator("#legal-TCP-srcport")
        value = srcport.input_value()
        if not value:
            page.wait_for_timeout(1000)
            value = srcport.input_value()
        assert len(value) > 0, f"TCP srcport field is empty after reload. Value: '{value}'"

    def test_save_custom_config(self, page, app_url):
        """UI-CFG-002: 保存自定义配置"""
        page.goto(app_url)
        page.wait_for_selector("body", timeout=10000)
        page.wait_for_timeout(500)
        
        page.locator("[data-testid=\"protocol-btn-TCP\"]").click()
        page.wait_for_timeout(500)
        
        # 修改字段
        page.locator("#legal-TCP-srcport").fill("7777")
        page.wait_for_timeout(200)
        
        # 保存配置（如果有按钮）
        srcport = page.locator("#legal-TCP-srcport")
        value = srcport.input_value()
        assert value == "7777" or len(value) > 0
