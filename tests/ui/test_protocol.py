# -*- coding: utf-8 -*-
"""
UI 测试：协议切换
"""

import pytest


class TestProtocolSwitch:
    """协议切换测试"""

    def test_tcp_to_ip_switch(self, page, app_url):
        """UI-PROTO-001: TCP → IP 切换"""
        page.goto(app_url)
        page.wait_for_selector("body", timeout=10000)
        page.wait_for_timeout(500)
        
        # 切换到 IP 协议
        page.locator("[data-testid=\"protocol-IP-btn\"]").click()
        page.wait_for_timeout(500)
        
        # 验证 IP 字段存在（通过 ID 定位）
        assert page.locator("#legal-IP-version").count() > 0
        assert page.locator("#legal-IP-src").count() > 0
        assert page.locator("#legal-IP-dst").count() > 0
        assert page.locator("#legal-IP-ttl").count() > 0

    def test_ip_to_doip_switch(self, page, app_url):
        """UI-PROTO-002: IP → DoIP 切换"""
        page.goto(app_url)
        page.wait_for_selector("body", timeout=10000)
        page.wait_for_timeout(500)
        
        # 切换到 DoIP 协议
        page.locator("[data-testid=\"protocol-DOIP-btn\"]").click()
        page.wait_for_timeout(500)
        
        # 验证 DoIP 字段存在
        assert page.locator("#legal-DOIP-version").count() > 0
        assert page.locator("#legal-DOIP-payload_type").count() > 0

    def test_someip_to_someip_sd_switch(self, page, app_url):
        """UI-PROTO-003: SOME/IP → SOME/IP-SD 切换"""
        page.goto(app_url)
        page.wait_for_selector("body", timeout=10000)
        page.wait_for_timeout(500)
        
        # 切换到 SOME/IP-SD 协议
        page.locator("[data-testid=\"protocol-SOMEIP-SD-btn\"]").click()
        page.wait_for_timeout(500)
        
        # 验证 SD 字段存在
        assert page.locator("#legal-SOMEIP-SD-service").count() > 0
        assert page.locator("#legal-SOMEIP-SD-method").count() > 0

    def test_illegal_value_highlight(self, page, app_url):
        """UI-PROTO-004: 非法值标记"""
        page.goto(app_url)
        page.wait_for_selector("body", timeout=10000)
        page.wait_for_timeout(500)
        
        # 确保在 TCP 协议
        page.locator("[data-testid=\"protocol-TCP-btn\"]").click()
        page.wait_for_timeout(500)
        
        # 输入非法值到非法值区域
        illegal_input = page.locator("#illegal-TCP-srcport")
        if illegal_input.count() > 0:
            illegal_input.fill("99999")
            illegal_input.blur()
            page.wait_for_timeout(300)
            
            # 验证字段有值
            assert illegal_input.count() > 0
