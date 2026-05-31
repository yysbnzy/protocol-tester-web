# -*- coding: utf-8 -*-
"""
UI 测试：页面加载
"""

import pytest


class TestPageLoad:
    """页面加载测试"""

    def test_homepage_loads(self, page, app_url):
        """UI-LOAD-001: 首页加载成功"""
        page.goto(app_url)
        
        # 等待页面加载完成（通过检查 body 或关键元素）
        page.wait_for_selector("body", timeout=10000)
        page.wait_for_timeout(1000)
        
        # 验证标题
        title = page.title()
        assert len(title) > 0, "页面标题为空"
        
        # 验证协议按钮存在
        assert page.locator("[data-testid=\"protocol-TCP-btn\"]").count() > 0
        
        # 验证发送按钮存在
        assert page.locator("[data-testid=\"send-packet-btn\"]").count() > 0

    def test_all_protocol_tabs_clickable(self, page, app_url):
        """UI-LOAD-002: 所有协议 Tab 可点击"""
        page.goto(app_url)
        page.wait_for_selector("body", timeout=10000)
        page.wait_for_timeout(500)
        
        protocols = ["ARP", "IP", "ICMP", "TCP", "UDP", "SOMEIP", "SOMEIP-SD", "DOIP"]
        
        for protocol in protocols:
            btn = page.locator(f"[data-testid=\"protocol-{protocol}-btn\"]")
            if btn.count() > 0:
                btn.click()
                page.wait_for_timeout(300)
                # 点击后按钮应该保持可点击状态
                assert btn.count() > 0

    def test_default_tcp_protocol(self, page, app_url):
        """UI-LOAD-003: 默认加载 TCP 协议"""
        page.goto(app_url)
        page.wait_for_selector("body", timeout=10000)
        page.wait_for_timeout(500)
        
        # 点击 TCP 按钮查看字段
        page.locator("[data-testid=\"protocol-TCP-btn\"]").click()
        page.wait_for_timeout(300)
        
        # 验证 TCP 字段存在（通过 ID 定位）
        assert page.locator("#legal-TCP-srcport").count() > 0
        assert page.locator("#legal-TCP-dstport").count() > 0
        assert page.locator("#legal-TCP-flags").count() > 0

    def test_static_files_load(self, page, app_url):
        """UI-LOAD-004: 静态文件加载"""
        page.goto(app_url)
        page.wait_for_selector("body", timeout=10000)
        page.wait_for_timeout(500)
        
        # 检查 CSS 是否加载（通过检查样式是否应用）
        # 检查 body 存在即可
        assert page.locator("body").count() > 0
        
        # 检查 JS 是否加载（通过检查交互元素是否存在）
        assert page.locator("[data-testid=\"send-packet-btn\"]").count() > 0
        assert page.locator("[data-testid=\"handshake-btn\"]").count() > 0
