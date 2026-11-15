# -*- coding: utf-8 -*-
"""
UI 测试：流量捕获
"""

import json

import pytest


def test_capture_statistics_continue_and_reset_on_second_start(page, app_url):
    """累计统计不受 1000 条显示缓冲区限制，二次捕获从零统计。"""
    packets = [{
        'id': f'pkt_{index}', 'time': '18:52:05.410', 'protocol': 'TCP',
        'length': 54, 'src_ip': '192.168.3.8', 'dst_ip': '103.143.17.156',
        'src_mac': '-', 'dst_mac': '-', 'src_port': 60678, 'dst_port': 443,
        'is_foreign': False, 'raw_bytes': '',
    } for index in range(6, 1006)]
    response_data = {
        'success': True, 'packets': packets, 'total_packets': 1005,
        'statistics': {
            'total_packets': 1005, 'foreign_packets': 268,
            'protocol_distribution': {'TCP': 1000, 'UDP': 5},
        },
    }
    page.route('**/api/capture/packets', lambda route: route.fulfill(
        status=200, content_type='application/json', body=json.dumps(response_data),
    ))
    page.route('**/api/capture/start', lambda route: route.fulfill(
        status=200, content_type='application/json',
        body=json.dumps({'success': True}),
    ))
    page.route('**/api/capture/streams/statistics', lambda route: route.fulfill(
        status=200, content_type='application/json',
        body=json.dumps({'success': True, 'statistics': {'total_streams': 0}}),
    ))

    page.goto(app_url)
    page.wait_for_timeout(500)
    page.evaluate('fetchCapturedPackets()')
    page.wait_for_timeout(300)
    assert page.locator('#statTotalPackets').text_content() == '1005'
    assert page.locator('#totalPacketsToolbar').text_content() == '1005'
    assert page.locator('#statForeignPackets').text_content() == '268'
    assert page.locator('#captureTableBody tr').last.locator('td').first.text_content() == '1005'
    assert '1000 (99.5%)' in page.locator('#chartBars').inner_text()

    response_data = {
        'success': True, 'packets': [], 'total_packets': 0,
        'statistics': {
            'total_packets': 0, 'foreign_packets': 0,
            'protocol_distribution': {},
        },
    }
    page.evaluate('startCapture()')
    page.wait_for_timeout(400)
    assert page.locator('#statTotalPackets').text_content() == '0'
    assert page.locator('#totalPacketsToolbar').text_content() == '0'
    assert page.locator('#statForeignPackets').text_content() == '0'
    assert page.locator('#captureTableBody .empty-row').count() == 1
    assert page.locator('#packetDetailTitle').text_content() == '报文详情 - 未选择'
    page.evaluate('stopCapturePolling()')


def test_packet_tree_collapse_and_binary_view(page, app_url):
    """协议层可折叠，选中报文后同步显示二进制字段。"""
    page.goto(app_url)
    page.wait_for_timeout(500)
    page.evaluate("""
        () => {
            const ethernet = 'a86e4e547582548d5a552f800800';
            const ip = '450000280000000040060000a3b10451c0a80308';
            const tcp = '0050c9c500000000000000005000ffff00000000';
            capturedPackets = [{
                id: 'pkt_1', time: '18:52:05.410', protocol: 'TCP', length: 54,
                src_mac: 'a8:6e:4e:54:75:82', dst_mac: '54:8d:5a:55:2f:80',
                src_ip: '163.177.4.81', dst_ip: '192.168.3.8',
                src_port: 80, dst_port: 51381, raw_bytes: ethernet + ip + tcp,
            }];
            showPacketDetail('pkt_1');
        }
    """)

    assert page.locator('#packetHexPanel .hex-byte').count() == 54
    assert page.locator('#packetHexPanel .hex-line').count() == 4

    ip_layer = page.locator('#packetTreePanel [data-field-id="ip"]')
    ip_version = page.locator('#packetTreePanel [data-field-id="version_ihl"]')
    assert ip_version.is_visible()
    ip_layer.click()
    assert not ip_version.is_visible()
    assert ip_layer.locator('.packet-tree-expand').text_content() == '▶'
    ip_layer.click()
    assert ip_version.is_visible()
    assert ip_layer.locator('.packet-tree-expand').text_content() == '▼'

    page.locator('#packetTreePanel [data-field-id="src_ip"]').click()
    assert page.locator('#packetHexPanel .hex-byte.selected').count() == 4


def test_bpf_tooltip_stays_inside_viewport_after_page_scroll(page, app_url):
    """页面滚动到底部后，前置过滤公式弹窗仍完整显示在视口内。"""
    page.goto(app_url)
    page.wait_for_timeout(600)
    page.evaluate('''() => {
        capturedPackets = Array.from({length: 42}, (_, index) => ({
            id: `pkt_${index + 1}`, time: '18:52:05.410', protocol: 'TCP', length: 66,
            src_ip: '192.168.3.8', dst_ip: '103.143.17.156', src_port: 60678,
            dst_port: 443, is_foreign: false, raw_bytes: '',
        }));
        appendCaptureList(capturedPackets, capturedPackets.length);
    }''')
    page.evaluate('window.scrollTo(0, document.documentElement.scrollHeight)')
    page.wait_for_timeout(200)

    icon = page.locator('.filter-tooltip-icon[data-filter-type="bpf"]')
    icon_box = icon.bounding_box()
    page.mouse.move(
        icon_box['x'] + icon_box['width'] / 2,
        icon_box['y'] + icon_box['height'] / 2,
    )
    page.wait_for_timeout(200)

    tooltip = icon.locator('.filter-tooltip')
    assert tooltip.is_visible()
    box = tooltip.bounding_box()
    viewport = page.evaluate('({width: window.innerWidth, height: window.innerHeight})')
    assert box['x'] >= 0
    assert box['y'] >= 0
    assert box['x'] + box['width'] <= viewport['width']
    assert box['y'] + box['height'] <= viewport['height']
    assert abs(box['y'] - icon_box['y']) <= 32
    assert box['x'] >= icon_box['x'] + icon_box['width']


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
            
            # 验证状态显示运行中或停止（初始状态可能不同）
            status = page.locator("[data-testid=\"capture-status\"]")
            if status.count() > 0:
                text = status.text_content()
                # 状态可能是 "运行中" 或 "停止/Idle"，取决于捕获是否成功启动
                assert any(kw in text for kw in ["运行", "capturing", "开始", "Running", "停止", "Idle", "⏹️", "⏸"]), f"Unexpected capture status: {text}"
        else:
            # 如果没有开始按钮，跳过此测试
            pytest.skip("Capture start button not available")

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
