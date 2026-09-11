# Debug script to check NIC loading
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from playwright.sync_api import sync_playwright
from tests.ui.conftest import wait_for_server, APP_URL

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    page = browser.new_page(viewport={"width": 1920, "height": 1080})
    
    # Capture console messages
    console_logs = []
    def handle_console(msg):
        console_logs.append(f"[{msg.type}] {msg.text}")
    page.on("console", handle_console)
    
    page.goto(APP_URL)
    page.wait_for_selector("body", timeout=10000)
    page.wait_for_timeout(3000)  # Wait for NICs to load
    
    # Check nicSelect value
    options = page.locator("#nicSelect option").all()
    print(f"NIC options ({len(options)}):")
    for opt in options:
        print(f"  value='{opt.get_attribute('value')}', text='{opt.text_content()}'")
    
    # Check nicInfo
    nic_info = page.locator("#nicInfo").text_content()
    print(f"nicInfo: '{nic_info}'")
    
    has_loadNics = page.evaluate("() => typeof loadNics === 'function'")
    print(f"loadNics function exists: {has_loadNics}")
    
    # Try calling loadNics manually and check result
    result = page.evaluate("""
        async () => {
            try {
                const select = document.getElementById('nicSelect');
                const info = document.getElementById('nicInfo');
                return {
                    selectExists: !!select,
                    selectHTML: select ? select.innerHTML.substring(0, 200) : 'no select',
                    infoText: info ? info.textContent : 'no info',
                    loadNicsType: typeof loadNics,
                    utilsLoaded: typeof updateNicInfo === 'function'
                };
            } catch(e) {
                return {error: e.message};
            }
        }
    """)
    print(f"DOM state: {result}")
    
    # Check console logs
    print("\nConsole logs:")
    for log in console_logs:
        print(f"  {log}")
    
    browser.close()
