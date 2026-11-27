/* ADB 连接、配对、辅助监听面板及弹窗。 */
let adbCurrentMethod = 'wired';
let adbInventory = { devices: [], pairable: [], connectable: [] };
let adbResultTimer = null;
let adbConnecting = false;

const adbMethodNames = {
    wired: '有线连接',
    wireless: '无线连接（5555）',
    wireless_pair: '无线配对连接',
};

async function adbRequest(url, options = {}) {
    const response = await fetch(url, options);
    const result = await response.json();
    if (!response.ok && !result.events) {
        throw new Error(result.message || `请求失败 (${response.status})`);
    }
    return result;
}

function updateAdbStatus(status = {}) {
    const connected = Boolean(status.connected);
    const listening = Boolean(status.listener_active);
    const button = document.getElementById('adbConnectionBtn');
    button.textContent = connected ? 'ADB已连接' : 'ADB未连接';
    button.classList.toggle('connected', connected);
    button.classList.toggle('disconnected', !connected);
    document.getElementById('adbStatusText').textContent = connected ? '已连接' : '未连接';
    document.getElementById('adbMethodText').textContent = connected
        ? (adbMethodNames[status.connection_type] || status.connection_type || '—') : '—';

    let target = '—';
    if (status.target_ip && status.adb_port) {
        target = `${status.target_ip}:${status.adb_port}`;
    } else if (status.serial) {
        target = status.serial;
    }
    document.getElementById('adbTargetText').textContent = target;
    const listener = document.getElementById('adbListenerText');
    listener.textContent = listening ? `监听中（${status.listener_port}）` : '未监听';
    listener.classList.toggle('listening', listening);
}

async function refreshAdbStatus() {
    try {
        const result = await adbRequest('/api/adb/status');
        updateAdbStatus(result.status || {});
    } catch (error) {
        updateAdbStatus({});
    }
}

function openAdbDialog() {
    const targetIp = document.getElementById('targetIp').value.trim();
    const targetPort = document.getElementById('targetPort').value;
    document.getElementById('adbListenerTarget').textContent = `${targetIp}:${targetPort}`;
    if (targetIp) {
        document.getElementById('adbWirelessIp').value = targetIp;
        if (!document.getElementById('adbPairIp').value) {
            document.getElementById('adbPairIp').value = targetIp;
        }
    }
    document.getElementById('adbDialogEvents').textContent = '';
    document.getElementById('adbConnectionModal').style.display = 'flex';
    refreshAdbDevices();
    document.querySelector('#adbConnectionModal .modal-close').focus();
}

function closeAdbDialog() {
    if (!adbConnecting) {
        document.getElementById('adbConnectionModal').style.display = 'none';
    }
}

function selectAdbMethod(method) {
    adbCurrentMethod = method;
    document.querySelectorAll('[data-adb-method]').forEach(button => {
        const active = button.dataset.adbMethod === method;
        button.classList.toggle('active', active);
        button.setAttribute('aria-selected', String(active));
    });
    document.querySelectorAll('[data-adb-panel]').forEach(panel => {
        panel.hidden = panel.dataset.adbPanel !== method;
    });
}

function fillAdbPairDevice() {
    const select = document.getElementById('adbPairableDevice');
    const option = select.selectedOptions[0];
    if (!option || !option.dataset.ip) return;
    document.getElementById('adbPairIp').value = option.dataset.ip;
    document.getElementById('adbPairPort').value = option.dataset.port;
    const connectable = adbInventory.connectable.find(item => item.target_ip === option.dataset.ip);
    if (connectable) {
        document.getElementById('adbConnectPort').value = connectable.port;
    }
}

async function refreshAdbDevices() {
    const refreshButton = document.querySelector('[data-testid="adb-refresh-devices"]');
    refreshButton.disabled = true;
    try {
        const result = await adbRequest('/api/adb/devices');
        adbInventory = {
            devices: result.devices || [],
            pairable: result.pairable || [],
            connectable: result.connectable || [],
        };
        if (result.status) updateAdbStatus(result.status);

        const wired = adbInventory.devices.filter(
            device => device.connection_type === 'wired' && device.state === 'device'
        );
        const wiredSelect = document.getElementById('adbWiredDevice');
        wiredSelect.replaceChildren();
        if (!wired.length) {
            wiredSelect.add(new Option('未检测到可用的有线设备', ''));
        } else {
            wired.forEach(device => wiredSelect.add(new Option(device.serial, device.serial)));
        }

        const pairSelect = document.getElementById('adbPairableDevice');
        pairSelect.replaceChildren();
        if (!adbInventory.pairable.length) {
            pairSelect.add(new Option('未发现时可在下方手动输入', ''));
        } else {
            pairSelect.add(new Option('请选择可配对设备', ''));
            adbInventory.pairable.forEach(device => {
                const option = new Option(
                    `${device.name} — ${device.target_ip}:${device.port}`,
                    `${device.target_ip}:${device.port}`
                );
                option.dataset.ip = device.target_ip;
                option.dataset.port = device.port;
                pairSelect.add(option);
            });
            if (adbInventory.pairable.length === 1) {
                pairSelect.selectedIndex = 1;
                fillAdbPairDevice();
            }
        }
        if (!result.adb_available) {
            document.getElementById('adbDialogEvents').textContent = result.message || '未检测到 adb';
        }
    } catch (error) {
        document.getElementById('adbDialogEvents').textContent = `设备识别失败：${error.message}`;
    } finally {
        refreshButton.disabled = false;
    }
}

function showAdbResult(success, title, message) {
    clearTimeout(adbResultTimer);
    const overlay = document.getElementById('adbResultModal');
    const card = document.getElementById('adbResultCard');
    card.classList.toggle('failed', !success);
    document.getElementById('adbResultIcon').textContent = success ? '✓' : '×';
    document.getElementById('adbResultTitle').textContent = title;
    document.getElementById('adbResultMessage').textContent = message || '';
    overlay.style.display = 'flex';

    adbResultTimer = setTimeout(() => {
        overlay.style.display = 'none';
        if (success) {
            document.getElementById('adbConnectionModal').style.display = 'none';
        }
    }, 2000);
}

async function submitAdbConnection() {
    if (adbConnecting) return;
    const mainTargetIp = document.getElementById('targetIp').value.trim();
    const targetPort = Number(document.getElementById('targetPort').value);
    let targetIp = mainTargetIp;
    const body = {
        method: adbCurrentMethod,
        target_port: targetPort,
    };

    if (adbCurrentMethod === 'wired') {
        body.serial = document.getElementById('adbWiredDevice').value;
    } else if (adbCurrentMethod === 'wireless') {
        targetIp = document.getElementById('adbWirelessIp').value.trim();
        body.adb_port = 5555;
    } else {
        targetIp = document.getElementById('adbPairIp').value.trim();
        body.pair_port = document.getElementById('adbPairPort').value.trim();
        body.pair_code = document.getElementById('adbPairCode').value.trim();
        body.connect_port = document.getElementById('adbConnectPort').value.trim();
    }
    body.target_ip = targetIp;

    adbConnecting = true;
    const submit = document.getElementById('adbConnectSubmit');
    submit.disabled = true;
    submit.textContent = '正在连接并监听...';
    document.getElementById('adbDialogEvents').textContent = '正在识别设备，请保持手机配对／无线调试页面可用。';

    try {
        const result = await adbRequest('/api/adb/connect', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });
        const events = result.events || [];
        document.getElementById('adbDialogEvents').textContent = events.join('\n');
        events.forEach(message => addLog(`[ADB] ${message}`));
        if (result.status) updateAdbStatus(result.status);

        if (result.success) {
            showAdbResult(true, '连接成功', 'ADB 已连接，目标端口已处于监听状态');
        } else {
            showAdbResult(
                false,
                result.stage === 'listener' ? '监听启动失败' : 'ADB 连接失败',
                result.message || '请检查连接参数后重试'
            );
        }
    } catch (error) {
        document.getElementById('adbDialogEvents').textContent = error.message;
        addLog(`[ADB] ✗ ${error.message}`);
        showAdbResult(false, '操作失败', error.message);
    } finally {
        adbConnecting = false;
        submit.disabled = false;
        submit.textContent = '连接并启动监听';
    }
}

document.addEventListener('keydown', event => {
    if (event.key === 'Escape') closeAdbDialog();
});

document.addEventListener('click', event => {
    if (event.target.id === 'adbConnectionModal') closeAdbDialog();
});

document.addEventListener('DOMContentLoaded', refreshAdbStatus);
