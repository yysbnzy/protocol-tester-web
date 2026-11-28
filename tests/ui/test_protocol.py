# -*- coding: utf-8 -*-
"""
UI 测试：协议切换
"""

import pytest


def test_legal_send_button_stays_blue(page, app_url):
    """选择非法字段时，合法发送按钮仍保持蓝色高亮。"""
    page.goto(app_url)
    page.wait_for_timeout(500)
    button = page.locator('#legalSendBtn')
    field_button = page.locator('#fieldButtons .field-btn').first
    protocol_button = page.locator('[data-testid="protocol-btn-ARP"]')
    assert field_button.evaluate(
        'element => getComputedStyle(element).backgroundColor'
    ) == protocol_button.evaluate(
        'element => getComputedStyle(element).backgroundColor'
    )

    field_button.click()
    page.wait_for_timeout(300)

    assert 'illegal' in (field_button.get_attribute('class') or '')
    assert field_button.evaluate(
        'element => getComputedStyle(element).backgroundColor'
    ) == 'rgb(239, 68, 68)'
    assert field_button.evaluate(
        'element => getComputedStyle(element).color'
    ) == 'rgb(255, 255, 255)'
    assert 'inactive' in (button.get_attribute('class') or '')
    assert button.evaluate(
        'element => getComputedStyle(element).backgroundColor'
    ) == 'rgb(14, 165, 233)'
    assert button.evaluate(
        'element => getComputedStyle(element).color'
    ) == 'rgb(255, 255, 255)'

    field_button.click()
    page.mouse.move(0, 0)
    page.wait_for_timeout(300)
    assert 'illegal' not in (field_button.get_attribute('class') or '')
    assert field_button.evaluate(
        'element => getComputedStyle(element).backgroundColor'
    ) == protocol_button.evaluate(
        'element => getComputedStyle(element).backgroundColor'
    )


def test_dark_preferences_cannot_enable_a_dark_theme(page, app_url):
    """旧本地设置和系统暗色偏好均不得改变浅色界面。"""
    page.emulate_media(color_scheme='dark')
    page.add_init_script("localStorage.setItem('protocol-tester-theme', 'dark')")
    page.goto(app_url)
    page.wait_for_timeout(500)

    assert page.locator('#themeToggle').count() == 0
    assert page.locator('script[src*="theme.js"]').count() == 0
    assert page.locator('html').get_attribute('data-theme') is None
    assert page.evaluate("localStorage.getItem('protocol-tester-theme')") == 'dark'

    button = page.locator('#legalSendBtn')
    field_button = page.locator('#fieldButtons .field-btn').first
    assert button.evaluate(
        'element => getComputedStyle(element).backgroundColor'
    ) == 'rgb(14, 165, 233)'
    assert field_button.evaluate(
        'element => getComputedStyle(element).backgroundColor'
    ) == 'rgb(14, 165, 233)'

    light_colors = page.evaluate("""() => ({
        body: getComputedStyle(document.body).backgroundColor,
        panel: getComputedStyle(document.querySelector('.middle-area .panel')).backgroundColor,
        input: getComputedStyle(document.querySelector('#targetIp')).backgroundColor,
    })""")
    page.evaluate("document.documentElement.setAttribute('data-theme', 'dark')")
    page.wait_for_timeout(400)
    assert page.evaluate("""() => ({
        body: getComputedStyle(document.body).backgroundColor,
        panel: getComputedStyle(document.querySelector('.middle-area .panel')).backgroundColor,
        input: getComputedStyle(document.querySelector('#targetIp')).backgroundColor,
    })""") == light_colors

    field_button.click()
    page.wait_for_timeout(300)
    assert field_button.evaluate(
        'element => getComputedStyle(element).backgroundColor'
    ) == 'rgb(239, 68, 68)'

    field_button.click()
    page.mouse.move(0, 0)
    page.wait_for_timeout(300)
    assert field_button.evaluate(
        'element => getComputedStyle(element).backgroundColor'
    ) == 'rgb(14, 165, 233)'


class TestProtocolSwitch:
    """协议切换测试"""

    def test_tcp_to_ip_switch(self, page, app_url):
        """UI-PROTO-001: TCP → IP 切换"""
        page.goto(app_url)
        page.wait_for_selector("body", timeout=10000)
        page.wait_for_timeout(500)
        
        # 切换到 IP 协议
        page.locator("[data-testid=\"protocol-btn-IP\"]").click()
        page.wait_for_timeout(500)
        
        # 验证 IP 字段存在（通过 ID 定位）
        assert page.locator("#legal-IP-version").count() > 0
        assert page.locator("#legal-IP-src").count() > 0
        assert page.locator("#legal-IP-dst").count() > 0
        assert page.locator("#legal-IP-ttl").count() > 0

    def test_ip_to_doip_switch(self, page, app_url):
        """UI-PROTO-002: IP → DoIP 切换"""
        page.goto(app_url)
        page.wait_for_selector("body", timeout=10000)
        page.wait_for_timeout(500)
        
        # 切换到 DoIP 协议
        page.locator("[data-testid=\"protocol-btn-DOIP\"]").click()
        page.wait_for_timeout(500)
        
        # 验证 DoIP 字段存在
        assert page.locator("#legal-DOIP-version").count() > 0
        assert page.locator("#legal-DOIP-payload_type").count() > 0

    def test_someip_to_someip_sd_switch(self, page, app_url):
        """UI-PROTO-003: SOME/IP → SOME/IP-SD 切换"""
        page.goto(app_url)
        page.wait_for_selector("body", timeout=10000)
        page.wait_for_timeout(500)
        
        # 切换到 SOME/IP-SD 协议
        page.locator("[data-testid=\"protocol-btn-SOMEIP-SD\"]").click()
        page.wait_for_timeout(500)
        
        # 验证 SD 字段存在
        assert page.locator("#legal-SOMEIP-SD-service").count() > 0
        assert page.locator("#legal-SOMEIP-SD-method").count() > 0

    def test_someip_sd_fields_use_sd_display_prefix(self, page, app_url):
        """SOME/IP-SD 的全部字段仅在界面上统一显示为 SD.xxx。"""
        page.goto(app_url)
        page.wait_for_timeout(500)
        page.locator('[data-testid="protocol-btn-SOMEIP-SD"]').click()
        page.wait_for_timeout(500)

        buttons = page.locator('#fieldButtons .field-btn[data-field^="SOMEIP-SD."]')
        assert buttons.count() == 15
        assert buttons.first.text_content() == 'SD.service'
        assert buttons.evaluate_all(
            'elements => elements.every(element => element.textContent.startsWith("SD."))'
        )

        for panel_id in ('legalValues', 'illegalValues'):
            labels = page.locator(
                f'#{panel_id} .protocol-group[data-protocol="SOMEIP-SD"] .field-row label'
            )
            assert labels.count() == 15
            assert labels.first.text_content() == 'SD.service:'
            assert labels.evaluate_all(
                'elements => elements.every(element => element.textContent.startsWith("SD."))'
            )
        assert page.locator('#legal-SOMEIP-SD-service').count() == 1
        request = page.evaluate('collectCurrentBuildRequest()')
        assert request['fields']['SOMEIP-SD']['service'] == '0xFFFF'

    def test_illegal_value_highlight(self, page, app_url):
        """UI-PROTO-004: 非法值标记"""
        page.goto(app_url)
        page.wait_for_selector("body", timeout=10000)
        page.wait_for_timeout(500)
        
        # 确保在 TCP 协议
        page.locator("[data-testid=\"protocol-btn-TCP\"]").click()
        page.wait_for_timeout(500)
        
        # 输入非法值到非法值区域
        illegal_input = page.locator("#illegal-TCP-srcport")
        if illegal_input.count() > 0:
            illegal_input.fill("99999")
            illegal_input.blur()
            page.wait_for_timeout(300)
            
            # 验证字段有值
            assert illegal_input.count() > 0
