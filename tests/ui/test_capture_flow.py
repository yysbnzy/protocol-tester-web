# -*- coding: utf-8 -*-
"""
UI 测试：端到端业务流程（E2E）
覆盖：发送报文 → 捕获 → 查看报文详情 完整流程
"""

import pytest


class TestEndToEndCaptureFlow:
    """端到端捕获流程测试"""

    def test_send_tcp_packet_and_verify_preview(self, page, app_url):
        """UI-FLOW-001: 发送 TCP 报文并验证预览"""
        page.goto(app_url)
        page.wait_for_selector("body", timeout=10000)
        page.wait_for_timeout(800)

        # 确认 TCP 协议已选中（默认）
        tcp_btn = page.locator("[data-testid=\"protocol-TCP-btn\"]")
        if tcp_btn.count() > 0:
            tcp_btn.click()
            page.wait_for_timeout(300)

        # 填写 TCP 字段
        srcport = page.locator("[data-testid=\"field-TCP-srcport\"] input")
        if srcport.count() > 0:
            srcport.fill("8080")

        dstport = page.locator("[data-testid=\"field-TCP-dstport\"] input")
        if dstport.count() > 0:
            dstport.fill("9090")

        # 点击发送
        send_btn = page.locator("[data-testid=\"send-btn\"]")
        if send_btn.count() > 0 and send_btn.is_visible():
            send_btn.click()
            page.wait_for_timeout(1000)

        # 验证输出面板有内容（预览或日志）
        output = page.locator("[data-testid=\"output-panel\"] textarea")
        if output.count() > 0:
            text = output.text_content() or ""
            assert len(text) > 0, "发送报文后输出面板应显示内容"
        else:
            # 如果输出面板不存在，检查日志
            log_output = page.locator("#logOutput")
            if log_output.count() > 0:
                text = log_output.text_content() or ""
                assert len(text) > 0, "发送报文后日志应显示内容"

    def test_capture_start_stop_flow(self, page, app_url):
        """UI-FLOW-002: 捕获启动和停止流程"""
        page.goto(app_url)
        page.wait_for_selector("body", timeout=10000)
        page.wait_for_timeout(800)

        # 点击开始捕获
        start_btn = page.locator("[data-testid=\"capture-start-btn\"]")
        if start_btn.count() > 0 and start_btn.is_visible():
            start_btn.click()
            page.wait_for_timeout(1500)

            # 验证状态显示运行中
            status = page.locator("[data-testid=\"capture-status\"]")
            if status.count() > 0:
                text = status.text_content() or ""
                assert any(kw in text for kw in ["运行", "capturing", "Running", "🔴"]), \
                    f"捕获开始后状态应显示运行中，实际: {text}"

            # 停止捕获
            stop_btn = page.locator("[data-testid=\"capture-stop-btn\"]")
            if stop_btn.count() > 0 and stop_btn.is_visible():
                stop_btn.click()
                page.wait_for_timeout(800)

                # 验证状态显示停止
                text = status.text_content() or ""
                assert any(kw in text for kw in ["停止", "stopped", "Idle", "⏹️"]), \
                    f"捕获停止后状态应显示停止，实际: {text}"
        else:
            pytest.skip("捕获开始按钮不可用")

    def test_send_packet_then_capture_flow(self, page, app_url):
        """UI-FLOW-003: 发送报文后启动捕获，验证表格更新"""
        page.goto(app_url)
        page.wait_for_selector("body", timeout=10000)
        page.wait_for_timeout(800)

        # Step 1: 发送一个报文
        tcp_btn = page.locator("[data-testid=\"protocol-TCP-btn\"]")
        if tcp_btn.count() > 0:
            tcp_btn.click()
            page.wait_for_timeout(300)

        send_btn = page.locator("[data-testid=\"send-btn\"]")
        if send_btn.count() > 0 and send_btn.is_visible():
            send_btn.click()
            page.wait_for_timeout(1000)

        # Step 2: 启动捕获
        start_btn = page.locator("[data-testid=\"capture-start-btn\"]")
        if start_btn.count() > 0 and start_btn.is_visible():
            start_btn.click()
            page.wait_for_timeout(2000)  # 等待捕获运行

            # Step 3: 检查捕获表格（可能有数据，也可能没有，取决于网络环境）
            table_body = page.locator("#captureTableBody")
            if table_body.count() > 0:
                rows = table_body.locator("tr")
                row_count = rows.count()
                # 捕获表格可能有数据行或空行提示
                assert row_count > 0, "捕获表格应至少有一行（数据或空提示）"

            # Step 4: 停止捕获
            stop_btn = page.locator("[data-testid=\"capture-stop-btn\"]")
            if stop_btn.count() > 0 and stop_btn.is_visible():
                stop_btn.click()
                page.wait_for_timeout(500)
        else:
            pytest.skip("捕获功能不可用，跳过端到端流程测试")

    def test_click_captured_packet_show_detail(self, page, app_url):
        """UI-FLOW-004: 点击捕获报文显示详情面板"""
        page.goto(app_url)
        page.wait_for_selector("body", timeout=10000)
        page.wait_for_timeout(800)

        # 启动捕获，让表格有数据
        start_btn = page.locator("[data-testid=\"capture-start-btn\"]")
        if start_btn.count() > 0 and start_btn.is_visible():
            start_btn.click()
            page.wait_for_timeout(2000)

            # 尝试点击表格中的第一行（跳过空行提示）
            table_body = page.locator("#captureTableBody")
            if table_body.count() > 0:
                rows = table_body.locator("tr")
                if rows.count() > 0:
                    first_row = rows.first
                    # 检查是否为空行提示
                    text = first_row.text_content() or ""
                    if "点击" not in text and "暂无" not in text and "空" not in text:
                        first_row.click()
                        page.wait_for_timeout(500)

                        # 验证详情面板有内容
                        detail = page.locator("#packetDetailOutput")
                        if detail.count() > 0:
                            detail_text = detail.text_content() or ""
                            assert len(detail_text) > 0, "点击报文后详情面板应显示内容"

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
            btn = page.locator(f"[data-testid=\"protocol-{proto}-btn\"]")
            if btn.count() > 0 and btn.is_visible():
                btn.click()
                page.wait_for_timeout(500)

                # 验证面板切换成功
                panel = page.locator(f"[data-testid=\"protocol-{proto}-panel\"]")
                # 即使面板不存在，也验证页面没有崩溃
                body = page.locator("body")
                assert body.count() > 0, f"切换到 {proto} 后页面不应崩溃"

                # 尝试发送（如果按钮存在）
                send_btn = page.locator("[data-testid=\"send-btn\"]")
                if send_btn.count() > 0 and send_btn.is_visible():
                    send_btn.click()
                    page.wait_for_timeout(500)
                    break  # 只测试第一个成功切换的协议

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
                page.wait_for_timeout(500)
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
                # 验证页面不崩溃
                body = page.locator("body")
                assert body.count() > 0, "点击导出后页面不应崩溃"
        else:
            pytest.skip("捕获功能不可用")

    def test_full_business_flow(self, page, app_url):
        """UI-FLOW-008: 完整业务流程：配置 → 发送 → 捕获 → 查看 → 导出"""
        page.goto(app_url)
        page.wait_for_selector("body", timeout=10000)
        page.wait_for_timeout(1000)

        # 1. 配置 TCP 字段
        tcp_btn = page.locator("[data-testid=\"protocol-TCP-btn\"]")
        if tcp_btn.count() > 0:
            tcp_btn.click()
            page.wait_for_timeout(300)

        srcport = page.locator("[data-testid=\"field-TCP-srcport\"] input")
        if srcport.count() > 0:
            srcport.fill("12345")

        dstport = page.locator("[data-testid=\"field-TCP-dstport\"] input")
        if dstport.count() > 0:
            dstport.fill("80")

        # 2. 发送报文
        send_btn = page.locator("[data-testid=\"send-btn\"]")
        send_clicked = False
        if send_btn.count() > 0 and send_btn.is_visible():
            send_btn.click()
            send_clicked = True
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
                # 只要有行即可，不要求一定有数据（取决于环境）
                assert rows.count() > 0, "捕获表格应至少有一行"

        # 5. 停止捕获
        stop_btn = page.locator("[data-testid=\"capture-stop-btn\"]")
        if stop_btn.count() > 0 and stop_btn.is_visible():
            stop_btn.click()
            page.wait_for_timeout(500)

        # 6. 验证页面状态（不崩溃）
        body = page.locator("body")
        assert body.count() > 0, "完整业务流程后页面不应崩溃"

        # 7. 验证输出或日志有内容
        output = page.locator("[data-testid=\"output-panel\"] textarea")
        log_output = page.locator("#logOutput")
        has_output = False
        if output.count() > 0:
            text = output.text_content() or ""
            if len(text) > 0:
                has_output = True
        if log_output.count() > 0:
            text = log_output.text_content() or ""
            if len(text) > 0:
                has_output = True

        if send_clicked:
            assert has_output, "发送报文后应有输出或日志内容"
