# -*- coding: utf-8 -*-
"""Payload 与 PCAP 选包回填 UI 回归。"""


def test_payload_inputs_are_three_times_regular_field_height(page, app_url):
    page.goto(app_url)
    page.wait_for_timeout(800)
    page.locator('[data-testid="protocol-btn-DOIP"]').click()

    regular_height = page.locator('#legal-DOIP-version').evaluate(
        'element => element.getBoundingClientRect().height'
    )
    payload_inputs = page.locator('.field-row textarea[data-field="payload"]')
    assert payload_inputs.count() == 2
    assert page.locator('#fieldButtons [data-field="Payload.payload"]').count() == 1
    assert page.locator('#fieldButtons .field-btn').last.get_attribute(
        'data-field'
    ) == 'Payload.payload'
    assert page.locator('#legalValues .protocol-group').last.get_attribute(
        'data-protocol'
    ) == 'Payload'
    assert page.locator('#illegalValues .protocol-group').last.get_attribute(
        'data-protocol'
    ) == 'Payload'
    for index in range(payload_inputs.count()):
        payload_input = payload_inputs.nth(index)
        payload_height = payload_input.evaluate(
            'element => parseFloat(getComputedStyle(element).height)'
        )
        assert payload_height == regular_height * 3
        assert payload_input.locator('xpath=..').locator('label').count() == 0
        assert payload_input.evaluate('element => element.tagName') == 'TEXTAREA'
        assert payload_input.evaluate('element => element.wrap') == 'soft'
        assert payload_input.evaluate(
            'element => getComputedStyle(element).whiteSpace'
        ) == 'pre-wrap'
        assert payload_input.evaluate(
            'element => getComputedStyle(element).textAlign'
        ) == 'left'
        sizes = payload_input.evaluate('''element => ({
            input: element.getBoundingClientRect().width,
            row: element.parentElement.getBoundingClientRect().width
        })''')
        assert abs(sizes['input'] - sizes['row']) <= 1


def test_doip_payload_is_sent_to_real_builder(page, app_url):
    page.goto(app_url)
    page.wait_for_timeout(800)
    page.locator('[data-testid="protocol-btn-DOIP"]').click()
    page.locator('[data-testid="protocol-btn-TCP"]').click()
    page.locator('[data-testid="protocol-btn-ARP"]').click()
    page.locator('[data-testid="send-mode-select"]').select_option('simulate')
    page.locator('#legal-Payload-payload').fill('0E8010012233')
    request = page.evaluate('collectCurrentBuildRequest()')
    assert request['fields']['DOIP']['payload'] == '0E8010012233'
    assert 'payload' not in request['fields']['TCP']
    assert 'payload' not in request['fields']['IP']
    page.locator('[data-testid="send-btn"]').click()
    page.wait_for_timeout(700)
    log = page.locator('[data-testid="log-output"]').input_value()
    assert '未实际发送' in log
    assert '58 bytes' in log
    assert page.locator('#legal-DOIP-payload_len').input_value() == '6'


def test_shared_illegal_payload_exports_only_at_innermost_layer(page, app_url):
    page.goto(app_url)
    page.wait_for_timeout(800)
    page.locator('[data-testid="protocol-btn-DOIP"]').click()
    page.locator('[data-testid="protocol-btn-UDP"]').click()
    page.locator('[data-testid="field-btn-Payload-payload"]').click()
    page.locator('#illegal-Payload-payload').fill('abc')

    request = page.evaluate('collectCurrentBuildRequest()')
    assert request['fields']['DOIP']['payload'] == 'abc'
    assert 'payload' not in request['fields']['UDP']
    assert request['illegal_fields_map']['DOIP'] == ['DOIP.payload']
    assert request['illegal_values_map']['DOIP']['DOIP.payload'] == 'abc'

    with page.expect_download():
        page.locator('[data-testid="pcap-export-current-btn"]').click()
    assert '当前编辑报文已导出' in page.locator('[data-testid="log-output"]').input_value()


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
    assert page.locator('#legal-Payload-payload').input_value() == '0e8010012233'
    assert page.locator('#legal-TCP-dstport').input_value() == '13400'
    assert page.locator('[data-testid="target-ip"]').input_value() == '192.168.2.24'
    assert page.locator('[data-testid="send-mode-select"]').input_value() == 'raw'
    log = page.locator('[data-testid="log-output"]').input_value()
    assert '已回填第 1 条报文' in log
