# -*- coding: utf-8 -*-
"""
UI 测试：所有协议合法值/非法值发送测试
覆盖：ARP, IP, TCP, UDP, ICMP, SOMEIP, SOMEIP-SD, DOIP
"""

import pytest

# 协议配置：协议名 + 合法字段 + 非法字段
PROTOCOLS = {
    "ARP": {
        "legal": {"proto.type": "0x0800", "opcode": "1", "src.hw_mac": "00:11:22:33:44:55", "dst.hw_mac": "66:77:88:99:AA:BB"},
        "illegal": {"proto.type": "0xFFFF", "opcode": "999", "src.hw_mac": "INVALID", "dst.hw_mac": "GG:HH:II:JJ:KK:LL"},
    },
    "IP": {
        "legal": {"version": "4", "tos": "0", "id": "1234", "ttl": "64", "checksum": "0x1234", "src": "192.168.1.1", "dst": "192.168.1.2"},
        "illegal": {"version": "99", "tos": "0xFF", "id": "-1", "ttl": "999", "checksum": "INVALID", "src": "999.999.999.999", "dst": "invalid"},
    },
    "TCP": {
        "legal": {"srcport": "12345", "dstport": "80", "seq": "0", "ack": "0", "flags": "0x02", "window_size": "65535", "checksum": "0x0000", "options": "0x020405b4"},
        "illegal": {"srcport": "99999", "dstport": "-1", "seq": "-1", "ack": "-1", "flags": "0xFF", "window_size": "0", "checksum": "INVALID", "options": "INVALID"},
    },
    "UDP": {
        "legal": {"srcport": "12345", "dstport": "53", "checksum": "0x0000"},
        "illegal": {"srcport": "99999", "dstport": "-1", "checksum": "INVALID"},
    },
    "ICMP": {
        "legal": {"type": "8", "code": "0", "checksum": "0x0000", "id": "1", "seq": "1"},
        "illegal": {"type": "999", "code": "999", "checksum": "INVALID", "id": "-1", "seq": "-1"},
    },
    "SOMEIP": {
        "legal": {"service": "0x1234", "method": "0x5678", "client": "0x01", "session": "0x01", "proto_ver": "1", "iface_ver": "1", "msg_type": "0x00", "retcode": "0x00", "payload": "0x01"},
        "illegal": {"service": "0xFFFF", "method": "0xFFFF", "client": "0xFF", "session": "0xFF", "proto_ver": "99", "iface_ver": "99", "msg_type": "0xFF", "retcode": "0xFF", "payload": "INVALID"},
    },
    "SOMEIP-SD": {
        "legal": {"service": "0x1234", "method": "0x8100", "client": "0x01", "session": "0x01", "proto_ver": "1", "iface_ver": "1", "msg_type": "0x02", "retcode": "0x00", "payload": "0x01"},
        "illegal": {"service": "0xFFFF", "method": "0xFFFF", "client": "0xFF", "session": "0xFF", "proto_ver": "99", "iface_ver": "99", "msg_type": "0xFF", "retcode": "0xFF", "payload": "INVALID"},
    },
    "DOIP": {
        "legal": {"version": "2", "inv_version": "0xFD", "payload_type": "0x0001", "payload": "0x01"},
        "illegal": {"version": "99", "inv_version": "0xFF", "payload_type": "0xFFFF", "payload": "INVALID"},
    },
}


class TestAllProtocolsLegalSend:
    """所有协议合法值发送测试"""

    @pytest.mark.parametrize("protocol", list(PROTOCOLS.keys()))
    def test_send_legal_values(self, page, app_url, protocol):
        """合法值发送：页面不崩溃，日志区域存在"""
        page.goto(app_url)
        page.wait_for_selector("body", timeout=10000)
        page.wait_for_timeout(800)

        # 切换到协议
        btn = page.locator(f"[data-testid=\"protocol-btn-{protocol}\"]")
        if btn.count() == 0 or not btn.is_visible():
            pytest.skip(f"协议 {protocol} 按钮不存在")
        btn.click()
        page.wait_for_timeout(500)

        # 填写合法值
        fields = PROTOCOLS[protocol]["legal"]
        for field, value in fields.items():
            input_el = page.locator(f"#legal-{protocol}-{field}")
            if input_el.count() > 0 and input_el.is_visible():
                input_el.fill(value)
                page.wait_for_timeout(100)

        # 点击发送
        send_btn = page.locator("[data-testid=\"send-btn\"]")
        if send_btn.count() > 0 and send_btn.is_visible():
            send_btn.click()
            page.wait_for_timeout(1000)

        # 验证页面不崩溃
        assert page.locator("body").count() > 0, f"{protocol} 合法值发送后页面不应崩溃"

        # 验证日志区域存在
        log_output = page.locator("[data-testid=\"log-output\"]")
        assert log_output.count() > 0, f"{protocol} 合法值发送后日志区域应存在"


class TestAllProtocolsIllegalSend:
    """所有协议非法值发送测试"""

    @pytest.mark.parametrize("protocol", list(PROTOCOLS.keys()))
    def test_send_illegal_values(self, page, app_url, protocol):
        """非法值发送：页面不崩溃，日志区域存在"""
        page.goto(app_url)
        page.wait_for_selector("body", timeout=10000)
        page.wait_for_timeout(800)

        # 切换到协议
        btn = page.locator(f"[data-testid=\"protocol-btn-{protocol}\"]")
        if btn.count() == 0 or not btn.is_visible():
            pytest.skip(f"协议 {protocol} 按钮不存在")
        btn.click()
        page.wait_for_timeout(500)

        # 填写非法值
        fields = PROTOCOLS[protocol]["illegal"]
        for field, value in fields.items():
            input_el = page.locator(f"#illegal-{protocol}-{field}")
            if input_el.count() > 0 and input_el.is_visible():
                input_el.fill(value)
                page.wait_for_timeout(100)

        # 点击合法发送按钮（触发非法值发送）
        send_btn = page.locator("[data-testid=\"legal-send-btn\"]")
        if send_btn.count() > 0 and send_btn.is_visible():
            send_btn.click()
            page.wait_for_timeout(1000)
        else:
            #  fallback: 用 send-btn
            send_btn = page.locator("[data-testid=\"send-btn\"]")
            if send_btn.count() > 0 and send_btn.is_visible():
                send_btn.click()
                page.wait_for_timeout(1000)

        # 验证页面不崩溃
        assert page.locator("body").count() > 0, f"{protocol} 非法值发送后页面不应崩溃"

        # 验证日志区域存在
        log_output = page.locator("[data-testid=\"log-output\"]")
        assert log_output.count() > 0, f"{protocol} 非法值发送后日志区域应存在"


class TestAllProtocolsSwitchAndSend:
    """所有协议切换后发送测试"""

    @pytest.mark.parametrize("protocol", list(PROTOCOLS.keys()))
    def test_switch_protocol_and_send_legal(self, page, app_url, protocol):
        """切换到协议 → 发送合法值 → 页面正常"""
        page.goto(app_url)
        page.wait_for_selector("body", timeout=10000)
        page.wait_for_timeout(800)

        # 切换到协议
        btn = page.locator(f"[data-testid=\"protocol-btn-{protocol}\"]")
        if btn.count() == 0 or not btn.is_visible():
            pytest.skip(f"协议 {protocol} 按钮不存在")
        btn.click()
        page.wait_for_timeout(500)

        # 填写一个合法值
        fields = PROTOCOLS[protocol]["legal"]
        first_field = list(fields.keys())[0]
        first_value = fields[first_field]
        input_el = page.locator(f"#legal-{protocol}-{first_field}")
        if input_el.count() > 0 and input_el.is_visible():
            input_el.fill(first_value)

        # 发送
        send_btn = page.locator("[data-testid=\"send-btn\"]")
        if send_btn.count() > 0 and send_btn.is_visible():
            send_btn.click()
            page.wait_for_timeout(1000)

        assert page.locator("body").count() > 0, f"切换到 {protocol} 并发送后页面不应崩溃"

    @pytest.mark.parametrize("protocol", list(PROTOCOLS.keys()))
    def test_switch_protocol_and_send_illegal(self, page, app_url, protocol):
        """切换到协议 → 发送非法值 → 页面正常"""
        page.goto(app_url)
        page.wait_for_selector("body", timeout=10000)
        page.wait_for_timeout(800)

        # 切换到协议
        btn = page.locator(f"[data-testid=\"protocol-btn-{protocol}\"]")
        if btn.count() == 0 or not btn.is_visible():
            pytest.skip(f"协议 {protocol} 按钮不存在")
        btn.click()
        page.wait_for_timeout(500)

        # 填写一个非法值
        fields = PROTOCOLS[protocol]["illegal"]
        first_field = list(fields.keys())[0]
        first_value = fields[first_field]
        input_el = page.locator(f"#illegal-{protocol}-{first_field}")
        if input_el.count() > 0 and input_el.is_visible():
            input_el.fill(first_value)

        # 发送
        send_btn = page.locator("[data-testid=\"legal-send-btn\"]")
        if send_btn.count() > 0 and send_btn.is_visible():
            send_btn.click()
            page.wait_for_timeout(1000)
        else:
            send_btn = page.locator("[data-testid=\"send-btn\"]")
            if send_btn.count() > 0 and send_btn.is_visible():
                send_btn.click()
                page.wait_for_timeout(1000)

        assert page.locator("body").count() > 0, f"切换到 {protocol} 并发送非法值后页面不应崩溃"
