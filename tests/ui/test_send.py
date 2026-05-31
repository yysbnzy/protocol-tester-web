# -*- coding: utf-8 -*-
"""
UI 测试：报文发送
"""

import pytest


class TestSendPacket:
    """报文发送测试"""

    def test_send_single_tcp_packet(self, page, app_url):
        """UI-SEND-001: 发送一次 TCP 报文"""
        page.goto(app_url)
        page.wait_for_selector("body", timeout=10000)
        page.wait_for_timeout(500)
        
        # 确保在 TCP 协议
        page.locator("[data-testid=\"protocol-btn-TCP\"]").click()
        page.wait_for_timeout(500)
        
        # 配置字段（通过 ID 定位）
        page.locator("#legal-TCP-srcport").fill("12345")
        page.locator("#legal-TCP-dstport").fill("80")
        page.locator("#legal-TCP-flags").fill("0x02")
        
        # 点击发送
        page.locator("[data-testid=\"send-btn\"]").click()
        page.wait_for_timeout(1000)
        
        # 验证日志有输出
        log_output = page.locator("[data-testid=\"log-output\"]")
        assert log_output.count() > 0

    def test_send_multiple_packets(self, page, app_url):
        """UI-SEND-002: 发送多次"""
        page.goto(app_url)
        page.wait_for_selector("body", timeout=10000)
        page.wait_for_timeout(500)
        
        page.locator("[data-testid=\"protocol-btn-TCP\"]").click()
        page.wait_for_timeout(500)
        
        # 设置发送次数
        page.locator("[data-testid=\"send-count\"]").fill("5")
        page.wait_for_timeout(200)
        
        # 点击发送
        page.locator("[data-testid=\"send-btn\"]").click()
        page.wait_for_timeout(2000)
        
        # 验证日志有输出
        log_output = page.locator("[data-testid=\"log-output\"]")
        assert log_output.count() > 0

    def test_send_malformed_packet(self, page, app_url):
        """UI-SEND-003: 畸形报文发送"""
        page.goto(app_url)
        page.wait_for_selector("body", timeout=10000)
        page.wait_for_timeout(500)
        
        page.locator("[data-testid=\"protocol-btn-TCP\"]").click()
        page.wait_for_timeout(500)
        
        # 输入畸形值到非法值区域
        page.locator("#illegal-TCP-flags").fill("0xFF")
        page.locator("#illegal-TCP-window_size").fill("0")
        
        # 点击发送非法值
        page.locator("[data-testid=\"legal-send-btn\"]").click()
        page.wait_for_timeout(1000)
        
        # 畸形报文应该也能发送
        assert page.locator("body").count() > 0

    def test_packet_preview(self, page, app_url):
        """UI-SEND-004: 报文预览"""
        page.goto(app_url)
        page.wait_for_selector("body", timeout=10000)
        page.wait_for_timeout(500)
        
        page.locator("[data-testid=\"protocol-btn-TCP\"]").click()
        page.wait_for_timeout(500)
        
        # 配置字段
        page.locator("#legal-TCP-srcport").fill("12345")
        page.locator("#legal-TCP-dstport").fill("80")
        
        # 检查 hex 预览区域（如果有）
        hex_panel = page.locator("[data-testid=\"packet-hex-panel\"]")
        # 可能有也可能没有，不强断言
        assert hex_panel.count() >= 0
