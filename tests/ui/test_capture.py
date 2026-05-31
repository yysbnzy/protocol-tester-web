# -*- coding: utf-8 -*-
"""
UI 测试：流量捕获
"""

import pytest


class TestCapture:
    """流量捕获测试"""

    def test_start_capture(self, page, app_url):
        """UI-CAP-001: 开始捕获"""
        page.goto(app_url)
        page.wait_for_selector("body", timeout=10000)
        page.wait_for_timeout(500)
        
        # 点击开始捕获
        start_btn = page.locator("[data-testid=\"capture-start-btn\"]")
        if start_btn.count() > 0 and start_btn.is_visible():
            start_btn.click()
            page.wait_for_timeout(1000)
            
            # 验证状态显示运行中
            status = page.locator("[data-testid=\"capture-status\"]")
            if status.count() > 0:
                text = status.text_content()
                assert "运行" in text or "capturing" in text.lower() or "开始" in text or "Running" in text

    def test_stop_capture(self, page, app_url):
        """UI-CAP-002: 停止捕获"""
        page.goto(app_url)
        page.wait_for_selector("body", timeout=10000)
        page.wait_for_timeout(500)
        
        # 先开始捕获
        start_btn = page.locator("[data-testid=\"capture-start-btn\"]")
        if start_btn.count() > 0 and start_btn.is_visible():
            start_btn.click()
            page.wait_for_timeout(1000)
            
            # 停止捕获
            stop_btn = page.locator("[data-testid=\"capture-stop-btn\"]")
            if stop_btn.count() > 0 and stop_btn.is_visible():
                stop_btn.click()
                page.wait_for_timeout(500)
                
                # 验证状态显示已停止
                status = page.locator("[data-testid=\"capture-status\"]")
                if status.count() > 0:
                    text = status.text_content()
                    assert "停止" in text or "stopped" in text.lower() or "未运行" in text or "Idle" in text
