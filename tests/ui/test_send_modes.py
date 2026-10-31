# -*- coding: utf-8 -*-
"""发送模式 UI 精准回归：模式真实生效，不允许静默切换"""


def select_single_protocol(page, protocol):
    target = page.locator(f'[data-testid="protocol-btn-{protocol}"]')
    if 'active' not in (target.get_attribute('class') or ''):
        target.click()
        page.wait_for_timeout(200)
    active = page.locator('.protocol-btn.active').evaluate_all(
        '(nodes) => nodes.map(node => node.dataset.protocol)'
    )
    for name in active:
        if name != protocol:
            page.locator(f'[data-testid="protocol-btn-{name}"]').click()
            page.wait_for_timeout(100)


def test_simulate_builds_but_does_not_call_send(page, app_url):
    page.goto(app_url)
    page.wait_for_timeout(1000)
    select_single_protocol(page, 'TCP')
    page.locator('[data-testid="send-mode-select"]').select_option('simulate')

    sent = []
    page.route('**/api/scapy/send', lambda route: sent.append(route.request) or route.continue_())
    page.locator('[data-testid="send-btn"]').click()
    page.wait_for_timeout(1000)

    log = page.locator('[data-testid="log-output"]').input_value()
    assert '未实际发送' in log
    assert len(sent) == 0


def test_raw_mode_is_passed_to_backend(page, app_url):
    page.goto(app_url)
    page.wait_for_timeout(1000)
    select_single_protocol(page, 'ARP')
    page.locator('[data-testid="send-mode-select"]').select_option('raw')

    bodies = []

    def fake_send(route):
        bodies.append(route.request.post_data_json)
        route.fulfill(status=200, content_type='application/json', body=(
            '{"success":true,"sent":1,"mode":"raw","message":"ok",'
            '"ethernet":{"src":"00:11:22:33:44:55",'
            '"dst":"ff:ff:ff:ff:ff:ff","type":"0x0806"}}'
        ))

    page.route('**/api/scapy/send', fake_send)
    page.locator('[data-testid="send-btn"]').click()
    page.wait_for_timeout(1000)

    assert len(bodies) == 1
    assert bodies[0]['mode'] == 'raw'
    assert '以太网' in page.locator('[data-testid="log-output"]').input_value()


def test_socket_arp_is_rejected_before_send(page, app_url):
    page.goto(app_url)
    page.wait_for_timeout(1000)
    select_single_protocol(page, 'ARP')
    page.locator('[data-testid="send-mode-select"]').select_option('socket')

    requests = []
    page.route('**/api/scapy/**', lambda route: requests.append(route.request) or route.continue_())
    page.locator('[data-testid="send-btn"]').click()
    page.wait_for_timeout(500)

    log = page.locator('[data-testid="log-output"]').input_value()
    assert '不支持 socket 模式' in log
    assert len(requests) == 0
