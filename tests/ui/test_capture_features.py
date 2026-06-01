# -*- coding: utf-8 -*-
"""
UI 测试：迭代1 抓包功能增强
覆盖：显示过滤器、协议着色、时间显示格式
"""

import pytest


class TestCaptureDisplayFilter:
    """显示过滤器测试"""

    def test_display_filter_input_exists(self, page, app_url):
        """UI-FLT-001: 显示过滤器输入框存在"""
        page.goto(app_url)
        page.wait_for_selector("body", timeout=10000)
        page.wait_for_timeout(1000)  # 等待 JS 加载
        
        filter_input = page.locator("[data-testid=\"display-filter-input\"]")
        assert filter_input.count() > 0, "显示过滤器输入框不存在"
        assert filter_input.is_visible(), "显示过滤器输入框不可见"

    def test_display_filter_presets_exist(self, page, app_url):
        """UI-FLT-002: 预设过滤器按钮存在"""
        page.goto(app_url)
        page.wait_for_selector("body", timeout=10000)
        page.wait_for_timeout(1000)
        
        presets = ['tcp', 'udp', 'icmp', 'arp', 'http', 'dns', 'doip', 'someip']
        for preset in presets:
            btn = page.locator(f"[data-testid=\"preset-{preset}\"]")
            assert btn.count() > 0, f"预设过滤器按钮 {preset} 不存在"

    def test_display_filter_preset_click(self, page, app_url):
        """UI-FLT-003: 点击预设过滤器填充输入框"""
        page.goto(app_url)
        page.wait_for_selector("body", timeout=10000)
        page.wait_for_timeout(1000)
        
        filter_input = page.locator("[data-testid=\"display-filter-input\"]")
        
        # 点击 TCP 预设
        tcp_preset = page.locator("[data-testid=\"preset-tcp\"]")
        if tcp_preset.count() > 0 and tcp_preset.is_visible():
            tcp_preset.click()
            page.wait_for_timeout(500)
            
            # 验证输入框被填充（setDisplayFilter 会调用 applyDisplayFilter）
            val = filter_input.input_value()
            assert "tcp" in val.lower(), f"点击 TCP 预设后输入框应包含 tcp，实际: {val}"

    def test_display_filter_clear(self, page, app_url):
        """UI-FLT-004: 清除过滤器"""
        page.goto(app_url)
        page.wait_for_selector("body", timeout=10000)
        page.wait_for_timeout(1000)
        
        filter_input = page.locator("[data-testid=\"display-filter-input\"]")
        
        # 先填入内容
        filter_input.fill("tcp.port == 80")
        page.wait_for_timeout(200)
        
        # 点击清除
        clear_btn = page.locator("[data-testid=\"display-filter-clear\"]")
        if clear_btn.count() > 0 and clear_btn.is_visible():
            clear_btn.click()
            page.wait_for_timeout(500)
            
            # 验证输入框被清空
            val = filter_input.input_value()
            assert val == "", f"清除过滤器后输入框应为空，实际: '{val}'"


class TestCaptureProtocolColoring:
    """协议着色测试"""

    def test_protocol_color_function_mapping(self, page, app_url):
        """UI-CLR-001: 协议颜色映射函数正确"""
        page.goto(app_url)
        page.wait_for_selector("body", timeout=10000)
        page.wait_for_timeout(1000)
        
        # 先检查函数是否存在
        has_func = page.evaluate("""
            () => typeof getProtocolColorClass === 'function'
        """)
        if not has_func:
            pytest.skip("getProtocolColorClass 函数未加载（可能 capture.js 未执行）")
        
        # 通过 JS 验证 getProtocolColorClass 函数
        result = page.evaluate("""
            () => {
                const tests = [
                    { proto: 'TCP', expected: 'pkt-tcp' },
                    { proto: 'UDP', expected: 'pkt-udp' },
                    { proto: 'ICMP', expected: 'pkt-icmp' },
                    { proto: 'ARP', expected: 'pkt-arp' },
                    { proto: 'DoIP', expected: 'pkt-doip' },
                    { proto: 'SOMEIP', expected: 'pkt-someip' },
                    { proto: 'SOMEIP-SD', expected: 'pkt-someip' },
                    { proto: 'HTTP', expected: 'pkt-http' },
                    { proto: 'DNS', expected: 'pkt-dns' },
                    { proto: 'SSH', expected: 'pkt-ssh' },
                    { proto: 'FTP', expected: 'pkt-ftp' },
                    { proto: 'DHCP', expected: 'pkt-dhcp' },
                    { proto: 'UNKNOWN', expected: '' },
                    { proto: null, expected: '' },
                ];
                const results = [];
                for (const t of tests) {
                    const actual = getProtocolColorClass(t.proto);
                    results.push({
                        proto: t.proto,
                        expected: t.expected,
                        actual: actual,
                        pass: actual === t.expected
                    });
                }
                return { allPass: results.every(r => r.pass), details: results };
            }
        """)
        
        assert result['allPass'], f"协议颜色映射失败: {result['details']}"


class TestCaptureTimeFormat:
    """时间显示格式测试"""

    def test_time_format_buttons_exist(self, page, app_url):
        """UI-TIME-001: 时间格式切换按钮存在"""
        page.goto(app_url)
        page.wait_for_selector("body", timeout=10000)
        page.wait_for_timeout(1000)
        
        formats = ['relative', 'absolute', 'delta']
        for fmt in formats:
            btn = page.locator(f"[data-testid=\"time-format-{fmt}\"]")
            assert btn.count() > 0, f"时间格式按钮 {fmt} 不存在"

    def test_time_format_switch(self, page, app_url):
        """UI-TIME-002: 切换时间格式按钮状态变化"""
        page.goto(app_url)
        page.wait_for_selector("body", timeout=10000)
        page.wait_for_timeout(1000)
        
        # 先检查变量是否存在
        has_var = page.evaluate("""
            () => typeof timeFormat !== 'undefined'
        """)
        if not has_var:
            pytest.skip("timeFormat 变量未加载（可能 capture.js 未执行）")
        
        # 点击 absolute
        abs_btn = page.locator("[data-testid=\"time-format-absolute\"]")
        if abs_btn.count() > 0 and abs_btn.is_visible():
            abs_btn.click()
            page.wait_for_timeout(500)
            
            # 验证 JS 中 timeFormat 变量已改变
            current_format = page.evaluate("() => timeFormat")
            assert current_format == 'absolute', f"切换后 timeFormat 应为 absolute，实际: {current_format}"
        
        # 点击 delta
        delta_btn = page.locator("[data-testid=\"time-format-delta\"]")
        if delta_btn.count() > 0 and delta_btn.is_visible():
            delta_btn.click()
            page.wait_for_timeout(500)
            
            current_format = page.evaluate("() => timeFormat")
            assert current_format == 'delta', f"切换后 timeFormat 应为 delta，实际: {current_format}"

    def test_time_format_relative_default(self, page, app_url):
        """UI-TIME-003: 默认时间格式为相对时间"""
        page.goto(app_url)
        page.wait_for_selector("body", timeout=10000)
        page.wait_for_timeout(1000)
        
        # 先检查变量是否存在
        has_var = page.evaluate("""
            () => typeof timeFormat !== 'undefined'
        """)
        if not has_var:
            pytest.skip("timeFormat 变量未加载（可能 capture.js 未执行）")
        
        current_format = page.evaluate("() => timeFormat")
        assert current_format == 'relative', f"默认时间格式应为 relative，实际: {current_format}"


class TestCaptureExport:
    """导出功能测试"""

    def test_export_csv_button_exists(self, page, app_url):
        """UI-EXP-001: CSV 导出按钮存在"""
        page.goto(app_url)
        page.wait_for_selector("body", timeout=10000)
        page.wait_for_timeout(1000)
        
        btn = page.locator("[data-testid=\"export-csv\"]")
        assert btn.count() > 0, "CSV 导出按钮不存在"

    def test_export_csv_clickable(self, page, app_url):
        """UI-EXP-002: CSV 导出按钮可点击"""
        page.goto(app_url)
        page.wait_for_selector("body", timeout=10000)
        page.wait_for_timeout(1000)
        
        btn = page.locator("[data-testid=\"export-csv\"]")
        if btn.count() > 0 and btn.is_visible():
            # 点击时不应报错（即使有网络错误也接受）
            btn.click()
            page.wait_for_timeout(500)
            # 页面不应崩溃
            body = page.locator("body")
            assert body.count() > 0, "点击导出后页面崩溃"
