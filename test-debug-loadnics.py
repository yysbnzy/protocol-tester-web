import subprocess
import time
import requests
from playwright.sync_api import sync_playwright

print('[Test] Starting Flask server...')
server = subprocess.Popen(
    ['python', '-c', 'from app import app, init_app; init_app(); app.run(host="0.0.0.0", port=5000, debug=False)'],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    cwd=r'C:\Users\Administrator\.openclaw\workspace\protocol-tester-web'
)

print('[Test] Waiting for server...')
for i in range(30):
    try:
        if requests.get('http://127.0.0.1:5000', timeout=2).status_code == 200:
            print('[Test] Server ready!')
            break
    except:
        pass
    time.sleep(1)
else:
    print('[Test] Server failed to start')
    server.kill()
    exit(1)

print('[Test] Starting Playwright UI test...')
with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    page = browser.new_page()
    
    console_logs = []
    page.on("console", lambda msg: console_logs.append(f"[{msg.type}] {msg.text}"))
    
    page.goto('http://127.0.0.1:5000', timeout=60000)
    page.wait_for_load_state('networkidle')
    time.sleep(3)
    
    print('[Test] Page loaded, checking if loadNics exists...')
    
    # Check if loadNics is defined
    loadNics_defined = page.evaluate("""typeof loadNics !== 'undefined'""")
    print(f'[Test] loadNics defined: {loadNics_defined}')
    
    # Check if nicSelect exists
    nicSelect_exists = page.evaluate("""document.getElementById('nicSelect') !== null""")
    print(f'[Test] nicSelect exists: {nicSelect_exists}')
    
    # Check initial options
    options = page.evaluate("""
        Array.from(document.getElementById('nicSelect').options).map(o => o.text)
    """)
    print(f'[Test] Initial options: {options}')
    
    # Manually call loadNics and check
    print('[Test] Manually calling loadNics()...')
    page.evaluate("""loadNics()""")
    time.sleep(2)
    
    # Check options after manual call
    options_after = page.evaluate("""
        Array.from(document.getElementById('nicSelect').options).map(o => o.text)
    """)
    print(f'[Test] Options after manual loadNics: {options_after}')
    
    print('[Test] Console logs:')
    for log in console_logs:
        print(f'  {log}')
    
    browser.close()

print('[Test] Done')
server.terminate()
server.wait(timeout=5)
