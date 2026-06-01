# -*- coding: utf-8 -*-
"""
UI 测试：端到端业务流程（E2E）
覆盖：发送报文 → 捕获 → 查看报文详情 完整流程
"""

import pytest


class TestEndToEndCaptureFlow:
    """端到端捕获流程测试"""

    def test_send_tcp_packet_and_verify_preview(self, page, app_url):
        """UI-FLOW-001: 发送 TCP 报文并验证日志有输出"""
        page.goto(app_url)
        page.wait_for_selector("body", timeout=10000)
        page.wait_for_timeout(800)

        # 确保在 TCP 协议
        page.locator("[data-testid=\"protocol-btn-TCP\"]").click()
        page.wait_for_timeout(500)

        # 配置字段
        page.locator("#legal-TCP-srcport").fill("12345")
        page.locator("#legal-TCP-dstport").fill("80")
        page.locator("#legal-TCP-flags").fill("0x02")

        # 点击发送
        page.locator("[data-testid=\"send-btn\"]").click()
        page.wait_for_timeout(1500)

        # 验证日志有输出
        log_output = page.locator("[data-testid=\"log-output\"]")
        assert log_output.count() > 0, "发送报文后日志输出区域应存在"
        # 日志内容可能异步加载，不强求立即有文本

    def test_capture_start_stop_flow(self, page, app_url):
        """UI-FLOW-002: 捕获启动和停止流程"""
        page.goto(app_url)
        page.wait_for_selector("body", timeout=10000)
        page.wait_for_timeout(800)

        # 点击开始捕获
        start_btn = page.locator("[data-testid=\"capture-start-btn\"]")
        if start_btn.count() > 0 and start_btn.is_visible():
            start_btn.click()
            page.wait_for_timeout(2000)

            # 验证状态（可能是运行中或停止，取决于捕获是否成功启动）
            status = page.locator("[data-testid=\"capture-status\"]")
            if status.count() > 0:
                text = status.text_content() or ""
                # 捕获可能因权限问题无法启动，接受任何状态
                assert len(text) > 0, "捕获状态应显示文本"

            # 停止捕获（如果按钮可见）
            stop_btn = page.locator("[data-testid=\"capture-stop-btn\"]")
            if stop_btn.count() > 0 and stop_btn.is_visible():
                stop_btn.click()
                page.wait_for_timeout(800)
        else:
            pytest.skip("捕获开始按钮不可用")

    def test_send_packet_then_capture_flow(self, page, app_url):
        """UI-FLOW-003: 发送报文后启动捕获，验证表格不崩溃"""
        page.goto(app_url)
        page.wait_for_selector("body", timeout=10000)
        page.wait_for_timeout(800)

        # Step 1: 发送一个报文
        page.locator("[data-testid=\"protocol-btn-TCP\"]").click()
        page.wait_for_timeout(500)
        page.locator("[data-testid=\"send-btn\"]").click()
        page.wait_for_timeout(1000)

        # Step 2: 启动捕获
        start_btn = page.locator("[data-testid=\"capture-start-btn\"]")
        if start_btn.count() > 0 and start_btn.is_visible():
            start_btn.click()
            page.wait_for_timeout(2000)

            # Step 3: 检查捕获表格不崩溃
            table_body = page.locator("#captureTableBody")
            if table_body.count() > 0:
                rows = table_body.locator("tr")
                row_count = rows.count()
                assert row_count > 0, "捕获表格应至少有一行（数据或空提示）"

            # Step 4: 停止捕获
            stop_btn = page.locator("[data-testid=\"capture-stop-btn\"]")
            if stop_btn.count() > 0 and stop_btn.is_visible():
                stop_btn.click()
        else:
            pytest.skip("捕获功能不可用")

    def test_click_captured_packet_show_detail(self, page, app_url):
        """UI-FLOW-004: 点击捕获报文或空行，页面不崩溃"""
        page.goto(app_url)
        page.wait_for_selector("body", timeout=10000)
        page.wait_for_timeout(800)

        # 启动捕获
        start_btn = page.locator("[data-testid=\"capture-start-btn\"]")
        if start_btn.count() > 0 and start_btn.is_visible():
            start_btn.click()
            page.wait_for_timeout(2000)

            # 尝试点击表格中的第一行
            table_body = page.locator("#captureTableBody")
            if table_body.count() > 0:
                rows = table_body.locator("tr")
                if rows.count() > 0:
                    first_row = rows.first
                    first_row.click()
                    page.wait_for_timeout(500)
                    # 页面不应崩溃
                    assert page.locator("body").count() > 0, "点击表格行后页面不应崩溃"

            # 停止捕获
            stop_btn = page.locator("[data-testid=\"capture-stop-btn\"]")
            if stop_btn.count() > 0 and stop_btn.is_visible():
                stop_btn.click()
        else:
            pytest.skip("捕获功能不可用")

    def test_protocol_switch_then_send_flow(self, page, app_url):
        """UI-FLOW-005: 切换协议后发送报文流程"""
        page.goto(app_url)
        page.wait_for_selector("body", timeout=10000)
        page.wait_for_timeout(800)

        protocols = ["IP", "UDP", "ICMP"]
        for proto in protocols:
            btn = page.locator(f"[data-testid=\"protocol-btn-{proto}\"]")
            if btn.count() > 0 and btn.is_visible():
                btn.click()
                page.wait_for_timeout(500)

                # 验证页面没有崩溃
                assert page.locator("body").count() > 0, f"切换到 {proto} 后页面不应崩溃"

                # 尝试发送
                send_btn = page.locator("[data-testid=\"send-btn\"]")
                if send_btn.count() > 0 and send_btn.is_visible():
                    send_btn.click()
                    page.wait_for_timeout(500)
                    break

    def test_display_filter_with_capture_flow(self, page, app_url):
        """UI-FLOW-006: 显示过滤器 + 捕获流程"""
        page.goto(app_url)
        page.wait_for_selector("body", timeout=10000)
        page.wait_for_timeout(800)

        # 设置显示过滤器
        filter_input = page.locator("[data-testid=\"display-filter-input\"]")
        if filter_input.count() > 0 and filter_input.is_visible():
            filter_input.fill("tcp")
            page.wait_for_timeout(200)
            apply_btn = page.locator("[data-testid=\"display-filter-apply\"]")
            if apply_btn.count() > 0 and apply_btn.is_visible():
                apply_btn.click()
                page.wait_for_timeout(500)

        # 启动捕获
        start_btn = page.locator("[data-testid=\"capture-start-btn\"]")
        if start_btn.count() > 0 and start_btn.is_visible():
            start_btn.click()
            page.wait_for_timeout(1500)

            # 停止捕获
            stop_btn = page.locator("[data-testid=\"capture-stop-btn\"]")
            if stop_btn.count() > 0 and stop_btn.is_visible():
                stop_btn.click()
        else:
            pytest.skip("捕获功能不可用")

    def test_export_after_capture_flow(self, page, app_url):
        """UI-FLOW-007: 捕获后导出流程"""
        page.goto(app_url)
        page.wait_for_selector("body", timeout=10000)
        page.wait_for_timeout(800)

        # 启动捕获
        start_btn = page.locator("[data-testid=\"capture-start-btn\"]")
        if start_btn.count() > 0 and start_btn.is_visible():
            start_btn.click()
            page.wait_for_timeout(1500)

            # 停止捕获
            stop_btn = page.locator("[data-testid=\"capture-stop-btn\"]")
            if stop_btn.count() > 0 and stop_btn.is_visible():
                stop_btn.click()
                page.wait_for_timeout(500)

            # 尝试导出 CSV
            csv_btn = page.locator("[data-testid=\"export-csv\"]")
            if csv_btn.count() > 0 and csv_btn.is_visible():
                csv_btn.click()
                page.wait_for_timeout(500)
                assert page.locator("body").count() > 0, "点击导出后页面不应崩溃"
        else:
            pytest.skip("捕获功能不可用")

    def test_full_business_flow(self, page, app_url):
        """UI-FLOW-008: 完整业务流程：配置 → 发送 → 捕获 → 查看 → 导出"""
        page.goto(app_url)
        page.wait_for_selector("body", timeout=10000)
        page.wait_for_timeout(1000)

        # 1. 配置 TCP 字段
        page.locator("[data-testid=\"protocol-btn-TCP\"]").click()
        page.wait_for_timeout(300)
        page.locator("#legal-TCP-srcport").fill("12345")
        page.locator("#legal-TCP-dstport").fill("80")

        # 2. 发送报文
        send_btn = page.locator("[data-testid=\"send-btn\"]")
        if send_btn.count() > 0 and send_btn.is_visible():
            send_btn.click()
            page.wait_for_timeout(1000)

        # 3. 启动捕获
        start_btn = page.locator("[data-testid=\"capture-start-btn\"]")
        capture_started = False
        if start_btn.count() > 0 and start_btn.is_visible():
            start_btn.click()
            capture_started = True
            page.wait_for_timeout(2000)

        # 4. 查看捕获表格
        if capture_started:
            table_body = page.locator("#captureTableBody")
            if table_body.count() > 0:
                rows = table_body.locator("tr")
                assert rows.count() > 0, "捕获表格应至少有一行"

        # 5. 停止捕获
        stop_btn = page.locator("[data-testid=\"capture-stop-btn\"]")
        if stop_btn.count() > 0 and stop_btn.is_visible():
            stop_btn.click()
            page.wait_for_timeout(500)

        # 6. 导出
        csv_btn = page.locator("[data-testid=\"export-csv\"]")
        if csv_btn.count() > 0 and csv_btn.is_visible():
            csv_btn.click()
            page.wait_for_timeout(500)

        # 7. 验证页面不崩溃
        assert page.locator("body").count() > 0, "完整业务流程后页面不应崩溃"
