# -*- coding: utf-8 -*-
"""
UI 自动化测试 fixtures
"""

import os
import pytest
from playwright.sync_api import sync_playwright


@pytest.fixture(scope="session")
def playwright_instance():
    """Playwright 实例"""
    playwright = sync_playwright().start()
    yield playwright
    playwright.stop()


@pytest.fixture
def browser(playwright_instance):
    """浏览器实例"""
    launch_options = {'headless': True}
    if os.environ.get('CHROMIUM_PATH'):
        launch_options['executable_path'] = os.environ['CHROMIUM_PATH']
    browser = playwright_instance.chromium.launch(**launch_options)
    yield browser
    browser.close()


@pytest.fixture
def context(browser):
    """浏览器上下文（每个测试独立）"""
    context = browser.new_context(
        viewport={"width": 1920, "height": 1080}
    )
    yield context
    context.close()


@pytest.fixture
def page(context):
    """页面实例"""
    page = context.new_page()
    yield page
    page.close()


@pytest.fixture
def app_url():
    """应用 URL"""
    return "http://127.0.0.1:5000"


@pytest.fixture
def logged_in_page(page, app_url):
    """已登录页面（如果有登录功能）"""
    page.goto(app_url)
    page.wait_for_selector("[data-testid=\"app-container\"]", timeout=10000)
    return page
