# -*- coding: utf-8 -*-
"""Payload 与 PCAP 选包回填 UI 回归。"""


def test_doip_payload_is_sent_to_real_builder(page, app_url):
    page.goto(app_url)
    page.wait_for_timeout(800)
    page.locator('[data-testid="protocol-btn-DOIP"]').click()
    page.locator('[data-testid="protocol-btn-TCP"]').click()
    page.locator('[data-testid="protocol-btn-ARP"]').click()
    page.locator('[data-testid="send-mode-select"]').select_option('simulate')
    page.locator('#legal-DOIP-payload').fill('0E8010012233')
    page.locator('[data-testid="send-btn"]').click()
    page.wait_for_timeout(700)
    log = page.locator('[data-testid="log-output"]').input_value()
    assert '未实际发送' in log
    assert '58 bytes' in log
    assert page.locator('#legal-DOIP-payload_len').input_value() == '6'


def test_pcap_selection_backfills_editor(page, app_url):
    page.goto(app_url)
    page.wait_for_timeout(800)
    result = {
        'success': True, 'filename': 'sample.pcap', 'packet_count': 1,
        'packets': [{
            'index': 0, 'summary': 'IP / TCP / DoIP', 'length': 68,
            'packet_hex': '00', 'protocols': ['IP', 'TCP', 'DOIP'],
            'fields': {
                'IP': {'src': '192.168.2.100', 'dst': '192.168.2.24'},
                'TCP': {'srcport': '40000', 'dstport': '13400'},
                'DOIP': {'version': '0x2', 'inv_version': '0xFD',
                         'payload_type': '0x8001', 'payload_len': '6',
                         'payload': '0e8010012233'},
            },
        }],
    }
    import json
    page.route('**/api/pcap/import', lambda route: route.fulfill(
        status=200, content_type='application/json', body=json.dumps(result),
    ))
    page.locator('[data-testid="pcap-import-btn"]').click()
    page.locator('[data-testid="pcap-file-input"]').set_input_files({
        'name': 'sample.pcap', 'mimeType': 'application/octet-stream',
        'buffer': b'placeholder',
    })
    page.locator('[data-testid="pcap-parse-btn"]').click()
    page.locator('[data-testid="pcap-fill-0"]').click()
    assert page.locator('#legal-DOIP-payload').input_value() == '0e8010012233'
    assert page.locator('#legal-TCP-dstport').input_value() == '13400'
    assert page.locator('[data-testid="target-ip"]').input_value() == '192.168.2.24'
    assert page.locator('[data-testid="send-mode-select"]').input_value() == 'raw'
    log = page.locator('[data-testid="log-output"]').input_value()
    assert '已回填第 1 条报文' in log
