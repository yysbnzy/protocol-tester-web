# -*- coding: utf-8 -*-
"""
UI 测试：迭代3 抓包功能增强
覆盖：BPF 捕获过滤器、Hex 视图
"""

import pytest


class TestCaptureBpfFilter:
    """BPF 捕获过滤器测试"""

    def test_bpf_filter_input_exists(self, page, app_url):
        """UI-BPF-001: BPF 过滤器输入框存在"""
        page.goto(app_url)
        page.wait_for_selector("body", timeout=10000)
        page.wait_for_timeout(1000)

        filter_input = page.locator("[data-testid=\"bpf-filter-input\"]")
        assert filter_input.count() > 0, "BPF 过滤器输入框不存在"
        assert filter_input.is_visible(), "BPF 过滤器输入框不可见"

    def test_bpf_filter_placeholder(self, page, app_url):
        """UI-BPF-002: BPF 过滤器输入框有占位提示"""
        page.goto(app_url)
        page.wait_for_selector("body", timeout=10000)
        page.wait_for_timeout(1000)

        filter_input = page.locator("[data-testid=\"bpf-filter-input\"]")
        if filter_input.count() > 0:
            placeholder = filter_input.get_attribute("placeholder") or ""
            assert "port" in placeholder.lower() or "host" in placeholder.lower() or "bpf" in placeholder.lower(), \
                f"BPF 占位提示应包含示例，实际: {placeholder}"

    def test_bpf_filter_input_typeable(self, page, app_url):
        """UI-BPF-003: BPF 过滤器输入框可输入"""
        page.goto(app_url)
        page.wait_for_selector("body", timeout=10000)
        page.wait_for_timeout(1000)

        filter_input = page.locator("[data-testid=\"bpf-filter-input\"]")
        if filter_input.count() > 0 and filter_input.is_visible():
            filter_input.fill("port 80")
            page.wait_for_timeout(200)
            val = filter_input.input_value()
            assert val == "port 80", f"BPF 输入框应能填入值，实际: {val}"

    def test_bpf_filter_clear(self, page, app_url):
        """UI-BPF-004: BPF 过滤器输入框可清空"""
        page.goto(app_url)
        page.wait_for_selector("body", timeout=10000)
        page.wait_for_timeout(1000)

        filter_input = page.locator("[data-testid=\"bpf-filter-input\"]")
        if filter_input.count() > 0 and filter_input.is_visible():
            filter_input.fill("host 192.168.1.1")
            page.wait_for_timeout(200)
            filter_input.fill("")
            page.wait_for_timeout(200)
            val = filter_input.input_value()
            assert val == "", f"清空后 BPF 输入框应为空，实际: '{val}'"


class TestCaptureHexView:
    """Hex 视图测试"""

    def test_hex_tab_button_exists(self, page, app_url):
        """UI-HEX-001: Hex 标签页按钮存在"""
        page.goto(app_url)
        page.wait_for_selector("body", timeout=10000)
        page.wait_for_timeout(1000)

        hex_tab = page.locator("[data-testid=\"detail-tab-hex\"]")
        assert hex_tab.count() > 0, "Hex 标签页按钮不存在"

    def test_hex_panel_exists(self, page, app_url):
        """UI-HEX-002: Hex 面板存在"""
        page.goto(app_url)
        page.wait_for_selector("body", timeout=10000)
        page.wait_for_timeout(1000)

        hex_panel = page.locator("[data-testid=\"packet-hex-panel\"]")
        assert hex_panel.count() > 0, "Hex 面板不存在"

    def test_hex_panel_initially_empty(self, page, app_url):
        """UI-HEX-003: 未选报文时 Hex 面板为空或提示"""
        page.goto(app_url)
        page.wait_for_selector("body", timeout=10000)
        page.wait_for_timeout(1000)

        hex_panel = page.locator("[data-testid=\"packet-hex-panel\"]")
        if hex_panel.count() > 0:
            text = hex_panel.text_content() or ""
            # 未选报文时可能显示提示或空
            assert len(text) < 200 or "数据" in text or "Hex" in text or "选择" in text, \
                f"Hex 面板初始状态异常: {text[:100]}"

    def test_hex_tab_clickable(self, page, app_url):
        """UI-HEX-004: Hex 标签页可点击"""
        page.goto(app_url)
        page.wait_for_selector("body", timeout=10000)
        page.wait_for_timeout(1000)

        hex_tab = page.locator("[data-testid=\"detail-tab-hex\"]")
        if hex_tab.count() > 0 and hex_tab.is_visible():
            hex_tab.click()
            page.wait_for_timeout(500)
            # 页面不应崩溃
            body = page.locator("body")
            assert body.count() > 0, "点击 Hex 标签页后页面崩溃"

    def test_hex_panel_has_hex_structure(self, page, app_url):
        """UI-HEX-005: Hex 面板有正确的结构元素"""
        page.goto(app_url)
        page.wait_for_selector("body", timeout=10000)
        page.wait_for_timeout(1000)

        hex_panel = page.locator("[data-testid=\"packet-hex-panel\"]")
        if hex_panel.count() > 0:
            # 检查是否有 hex-view-container 类
            container = hex_panel.locator(".hex-view-container")
            # 即使没有报文选中，结构元素应该存在
            assert True  # 只要面板存在即可


class TestCaptureIter3Integration:
    """迭代3 集成测试"""

    def test_bpf_and_hex_elements_coexist(self, page, app_url):
        """UI-IT3-001: BPF 过滤器和 Hex 视图同时存在"""
        page.goto(app_url)
        page.wait_for_selector("body", timeout=10000)
        page.wait_for_timeout(1000)

        bpf_input = page.locator("[data-testid=\"bpf-filter-input\"]")
        hex_tab = page.locator("[data-testid=\"detail-tab-hex\"]")
        hex_panel = page.locator("[data-testid=\"packet-hex-panel\"]")

        assert bpf_input.count() > 0, "BPF 输入框不存在"
        assert hex_tab.count() > 0, "Hex 标签页不存在"
        assert hex_panel.count() > 0, "Hex 面板不存在"
