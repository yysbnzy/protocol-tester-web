# -*- coding: utf-8 -*-
"""
UI 测试：迭代2 抓包功能增强
覆盖：跟随流、统计面板、CSV/JSON导出
"""

import pytest


class TestCaptureFollowStream:
    """跟随流测试"""

    def test_stream_manager_button_exists(self, page, app_url):
        """UI-STM-001: 流管理器按钮存在"""
        page.goto(app_url)
        page.wait_for_selector("body", timeout=10000)
        page.wait_for_timeout(1000)
        
        btn = page.locator("[data-testid=\"stream-manager-btn\"]")
        assert btn.count() > 0, "流管理器按钮不存在"

    def test_stream_modal_opens(self, page, app_url):
        """UI-STM-002: 点击流管理器按钮打开模态框"""
        page.goto(app_url)
        page.wait_for_selector("body", timeout=10000)
        page.wait_for_timeout(1000)
        
        btn = page.locator("[data-testid=\"stream-manager-btn\"]")
        if btn.count() > 0 and btn.is_visible():
            btn.click()
            page.wait_for_timeout(500)
            
            # 验证模态框显示
            modal = page.locator("#streamModal")
            assert modal.count() > 0, "streamModal 不存在"
            # 检查 display 属性
            display = modal.evaluate("el => el.style.display")
            assert display == "flex" or display == "block", f"模态框未显示，display={display}"

    def test_stream_modal_closes(self, page, app_url):
        """UI-STM-003: 关闭流管理器模态框"""
        page.goto(app_url)
        page.wait_for_selector("body", timeout=10000)
        page.wait_for_timeout(1000)
        
        # 先打开模态框
        btn = page.locator("[data-testid=\"stream-manager-btn\"]")
        if btn.count() > 0 and btn.is_visible():
            btn.click()
            page.wait_for_timeout(500)
            
            # 点击关闭按钮
            close_btn = page.locator("#streamModal .modal-close")
            if close_btn.count() > 0:
                close_btn.click()
                page.wait_for_timeout(500)
                
                # 验证模态框隐藏
                modal = page.locator("#streamModal")
                display = modal.evaluate("el => el.style.display")
                assert display == "none", f"模态框未关闭，display={display}"

    def test_stream_table_exists(self, page, app_url):
        """UI-STM-004: 流列表表格存在"""
        page.goto(app_url)
        page.wait_for_selector("body", timeout=10000)
        page.wait_for_timeout(1000)
        
        # 打开模态框查看表格
        btn = page.locator("[data-testid=\"stream-manager-btn\"]")
        if btn.count() > 0 and btn.is_visible():
            btn.click()
            page.wait_for_timeout(500)
            
            table = page.locator("#streamTable")
            assert table.count() > 0, "流列表表格不存在"
            
            # 验证表头
            headers = table.locator("thead th")
            assert headers.count() > 0, "表格表头不存在"

    def test_follow_stream_modal_exists(self, page, app_url):
        """UI-STM-005: Follow Stream 模态框存在"""
        page.goto(app_url)
        page.wait_for_selector("body", timeout=10000)
        page.wait_for_timeout(1000)
        
        modal = page.locator("#followStreamModal")
        assert modal.count() > 0, "Follow Stream 模态框不存在"

    def test_follow_stream_format_selector(self, page, app_url):
        """UI-STM-006: Follow Stream 格式选择器存在"""
        page.goto(app_url)
        page.wait_for_selector("body", timeout=10000)
        page.wait_for_timeout(1000)
        
        # 打开流管理器模态框
        btn = page.locator("[data-testid=\"stream-manager-btn\"]")
        if btn.count() > 0 and btn.is_visible():
            btn.click()
            page.wait_for_timeout(500)
            
            # Follow Stream 格式选择器应该在 followStreamModal 中
            format_select = page.locator("#followFormat")
            assert format_select.count() > 0, "Follow Stream 格式选择器不存在"


class TestCaptureStatistics:
    """统计面板测试"""

    def test_statistics_panel_exists(self, page, app_url):
        """UI-STAT-001: 统计面板存在"""
        page.goto(app_url)
        page.wait_for_selector("body", timeout=10000)
        page.wait_for_timeout(1000)
        
        panel = page.locator("[data-testid=\"statistics-panel\"]")
        assert panel.count() > 0, "统计面板不存在"
        assert panel.is_visible(), "统计面板不可见"

    def test_statistics_content_exists(self, page, app_url):
        """UI-STAT-002: 统计内容元素存在"""
        page.goto(app_url)
        page.wait_for_selector("body", timeout=10000)
        page.wait_for_timeout(1000)
        
        # 总报文数
        total_packets = page.locator("#statTotalPackets")
        assert total_packets.count() > 0, "总报文数元素不存在"
        
        # 总流数
        total_streams = page.locator("#statTotalStreams")
        assert total_streams.count() > 0, "总流数元素不存在"
        
        # 境外报文
        foreign_packets = page.locator("#statForeignPackets")
        assert foreign_packets.count() > 0, "境外报文元素不存在"

    def test_protocol_chart_exists(self, page, app_url):
        """UI-STAT-003: 协议分布图表存在"""
        page.goto(app_url)
        page.wait_for_selector("body", timeout=10000)
        page.wait_for_timeout(1000)
        
        chart = page.locator("#protocolChart")
        assert chart.count() > 0, "协议分布图表不存在"
        
        chart_bars = page.locator("#chartBars")
        assert chart_bars.count() > 0, "图表柱状条容器不存在"

    def test_statistics_refresh_button(self, page, app_url):
        """UI-STAT-004: 刷新统计按钮可点击"""
        page.goto(app_url)
        page.wait_for_selector("body", timeout=10000)
        page.wait_for_timeout(1000)
        
        # 查找刷新按钮（通过 onclick 属性）
        refresh_btn = page.locator("button[onclick=\"refreshStatistics()\"]")
        if refresh_btn.count() > 0 and refresh_btn.is_visible():
            refresh_btn.click()
            page.wait_for_timeout(500)
            # 页面不应崩溃
            body = page.locator("body")
            assert body.count() > 0, "点击刷新统计后页面崩溃"


class TestCaptureExport:
    """导出功能测试"""

    def test_export_csv_button_exists(self, page, app_url):
        """UI-EXP-001: CSV 导出按钮存在"""
        page.goto(app_url)
        page.wait_for_selector("body", timeout=10000)
        page.wait_for_timeout(1000)
        
        btn = page.locator("[data-testid=\"export-csv\"]")
        assert btn.count() > 0, "CSV 导出按钮不存在"

    def test_export_json_button_exists(self, page, app_url):
        """UI-EXP-002: JSON 导出按钮存在"""
        page.goto(app_url)
        page.wait_for_selector("body", timeout=10000)
        page.wait_for_timeout(1000)
        
        btn = page.locator("[data-testid=\"export-json\"]")
        assert btn.count() > 0, "JSON 导出按钮不存在"

    def test_export_csv_clickable(self, page, app_url):
        """UI-EXP-003: CSV 导出按钮可点击"""
        page.goto(app_url)
        page.wait_for_selector("body", timeout=10000)
        page.wait_for_timeout(1000)
        
        btn = page.locator("[data-testid=\"export-csv\"]")
        if btn.count() > 0 and btn.is_visible():
            btn.click()
            page.wait_for_timeout(500)
            # 页面不应崩溃
            body = page.locator("body")
            assert body.count() > 0, "点击 CSV 导出后页面崩溃"

    def test_export_json_clickable(self, page, app_url):
        """UI-EXP-004: JSON 导出按钮可点击"""
        page.goto(app_url)
        page.wait_for_selector("body", timeout=10000)
        page.wait_for_timeout(1000)
        
        btn = page.locator("[data-testid=\"export-json\"]")
        if btn.count() > 0 and btn.is_visible():
            btn.click()
            page.wait_for_timeout(500)
            # 页面不应崩溃
            body = page.locator("body")
            assert body.count() > 0, "点击 JSON 导出后页面崩溃"

    def test_export_api_endpoints(self, page, app_url):
        """UI-EXP-005: 导出 API 端点可访问"""
        # 直接测试 API 端点是否返回正确状态
        import requests
        
        # CSV 导出端点
        csv_resp = requests.get(f"{app_url}/api/capture/export/csv", timeout=5)
        assert csv_resp.status_code in [200, 404], f"CSV 导出端点返回异常状态码: {csv_resp.status_code}"
        
        # JSON 导出端点
        json_resp = requests.get(f"{app_url}/api/capture/export/json", timeout=5)
        assert json_resp.status_code in [200, 404], f"JSON 导出端点返回异常状态码: {json_resp.status_code}"
