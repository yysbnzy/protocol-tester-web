const { chromium } = require('playwright');
const { exec } = require('child_process');
const path = require('path');
const fs = require('fs');

const EXE_PATH = path.join(__dirname, 'dist', 'ProtocolTester.exe');
const BASE_URL = 'http://127.0.0.1:5000';
const SCREENSHOT_DIR = path.join(__dirname, 'test-screenshots');

// Ensure screenshot directory exists
if (!fs.existsSync(SCREENSHOT_DIR)) {
    fs.mkdirSync(SCREENSHOT_DIR, { recursive: true });
}

let exeProcess = null;
let browser = null;
let page = null;

async function startExe() {
    console.log('[Test] Starting EXE...');
    exeProcess = exec(`"${EXE_PATH}"`, {
        windowsHide: true
    });
    
    exeProcess.stdout.on('data', (data) => {
        console.log('[EXE]', data.toString().trim());
    });
    
    exeProcess.stderr.on('data', (data) => {
        console.error('[EXE Error]', data.toString().trim());
    });
    
    // Wait for server to start
    console.log('[Test] Waiting for server to start...');
    let retries = 30;
    while (retries > 0) {
        try {
            const response = await fetch(BASE_URL);
            if (response.ok) {
                console.log('[Test] Server is ready!');
                return;
            }
        } catch (e) {
            // Server not ready yet
        }
        await new Promise(r => setTimeout(r, 1000));
        retries--;
    }
    throw new Error('Server failed to start within 30 seconds');
}

async function takeScreenshot(name) {
    if (!page) return;
    const screenshotPath = path.join(SCREENSHOT_DIR, `${name}.png`);
    await page.screenshot({ path: screenshotPath, fullPage: true });
    console.log(`[Test] Screenshot saved: ${screenshotPath}`);
    return screenshotPath;
}

async function runTests() {
    let passed = 0;
    let failed = 0;
    
    async function test(name, fn) {
        try {
            console.log(`\n[Test] === ${name} ===`);
            await fn();
            console.log(`[Test] ✓ PASSED: ${name}`);
            passed++;
        } catch (error) {
            console.error(`[Test] ✗ FAILED: ${name}`);
            console.error(`[Test] Error: ${error.message}`);
            await takeScreenshot(`failed-${name.replace(/\s+/g, '-')}`);
            failed++;
        }
    }
    
    // Test 1: Page loads
    await test('Page loads with correct title', async () => {
        await page.goto(BASE_URL);
        await page.waitForLoadState('networkidle');
        const title = await page.title();
        if (!title.includes('协议字段测试工具')) {
            throw new Error(`Expected title to contain '协议字段测试工具', got: ${title}`);
        }
    });
    
    // Test 2: NIC dropdown loads
    await test('NIC dropdown loads with network interfaces', async () => {
        await page.waitForSelector('[data-testid="nic-select"]', { timeout: 10000 });
        const nicSelect = await page.locator('[data-testid="nic-select"]');
        const options = await nicSelect.locator('option').allTextContents();
        console.log(`[Test] NIC options: ${options.join(', ')}`);
        if (options.length <= 1 || options[0].includes('加载')) {
            throw new Error('NIC dropdown not populated with real interfaces');
        }
    });
    
    // Test 3: Protocol buttons exist
    await test('Protocol buttons are present', async () => {
        const protocols = ['ARP', 'IP', 'ICMP', 'TCP', 'UDP', 'SOMEIP', 'SOMEIP-SD', 'DOIP'];
        for (const protocol of protocols) {
            const btn = await page.locator(`[data-testid="protocol-btn-${protocol}"]`);
            const count = await btn.count();
            if (count === 0) {
                throw new Error(`Protocol button ${protocol} not found`);
            }
        }
        console.log(`[Test] All ${protocols.length} protocol buttons found`);
    });
    
    // Test 4: Click protocol switches fields
    await test('Clicking protocol updates field buttons', async () => {
        await page.click('[data-testid="protocol-btn-TCP"]');
        await page.waitForTimeout(500);
        const fieldButtons = await page.locator('[data-testid="field-buttons"] button');
        const count = await fieldButtons.count();
        console.log(`[Test] TCP field buttons: ${count}`);
        if (count === 0) {
            throw new Error('No field buttons shown for TCP');
        }
    });
    
    // Test 5: Legal values section exists
    await test('Legal values section is present', async () => {
        const legalValues = await page.locator('[data-testid="legal-values"]');
        const count = await legalValues.count();
        if (count === 0) {
            throw new Error('Legal values section not found');
        }
    });
    
    // Test 6: Send controls exist
    await test('Send controls are present', async () => {
        const controls = [
            'target-ip',
            'target-port',
            'send-count',
            'send-interval',
            'send-btn',
            'handshake-btn'
        ];
        for (const control of controls) {
            const el = await page.locator(`[data-testid="${control}"]`);
            const count = await el.count();
            if (count === 0) {
                throw new Error(`Control ${control} not found`);
            }
        }
    });
    
    // Test 7: Capture section exists
    await test('Capture section is present', async () => {
        const captureBtn = await page.locator('[data-testid="capture-start-btn"]');
        const count = await captureBtn.count();
        if (count === 0) {
            throw new Error('Capture start button not found');
        }
    });
    
    // Test 8: Log output exists
    await test('Log output area is present', async () => {
        const logOutput = await page.locator('[data-testid="log-output"]');
        const count = await logOutput.count();
        if (count === 0) {
            throw new Error('Log output not found');
        }
    });
    
    // Test 9: Send mode selector works
    await test('Send mode selector has options', async () => {
        const select = await page.locator('[data-testid="send-mode-select"]');
        const options = await select.locator('option').allTextContents();
        console.log(`[Test] Send modes: ${options.join(', ')}`);
        const expectedModes = ['socket', 'simulate', 'raw', 'npcap'];
        for (const mode of expectedModes) {
            const hasMode = options.some(o => o.toLowerCase().includes(mode));
            if (!hasMode) {
                throw new Error(`Send mode ${mode} not found in options`);
            }
        }
    });
    
    // Test 10: API connectivity
    await test('Backend API is responsive', async () => {
        const response = await page.evaluate(async () => {
            const res = await fetch('/api/nics');
            return { status: res.status, ok: res.ok };
        });
        console.log(`[Test] API response: ${JSON.stringify(response)}`);
        if (!response.ok) {
            throw new Error(`API returned status ${response.status}`);
        }
    });
    
    // Take final screenshot
    await takeScreenshot('final-state');
    
    console.log(`\n========================================`);
    console.log(`[Test] Results: ${passed} passed, ${failed} failed`);
    console.log(`========================================`);
    
    return { passed, failed };
}

async function main() {
    try {
        // Start EXE
        await startExe();
        
        // Launch browser
        console.log('[Test] Launching browser...');
        browser = await chromium.launch({ headless: true });
        page = await browser.newPage();
        
        // Run tests
        const results = await runTests();
        
        // Cleanup
        console.log('[Test] Cleaning up...');
        if (browser) await browser.close();
        if (exeProcess) {
            exeProcess.kill();
            console.log('[Test] EXE process terminated');
        }
        
        process.exit(results.failed > 0 ? 1 : 0);
    } catch (error) {
        console.error('[Test] Fatal error:', error.message);
        if (browser) await browser.close();
        if (exeProcess) exeProcess.kill();
        process.exit(1);
    }
}

main();
