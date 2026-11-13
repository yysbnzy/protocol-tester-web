let importedPcapPackets = [];
let selectedPcapPacket = null;

function openPcapImport() {
    document.getElementById('pcapImportModal').style.display = 'flex';
}

function closePcapImport() {
    document.getElementById('pcapImportModal').style.display = 'none';
}

function closePcapImportOnBackdrop(event) {
    if (event.target.id === 'pcapImportModal') closePcapImport();
}

document.addEventListener('keydown', event => {
    if (event.key === 'Escape') closePcapImport();
});

async function parsePcapFile() {
    const input = document.getElementById('pcapFileInput');
    const status = document.getElementById('pcapImportStatus');
    if (!input.files.length) {
        status.textContent = '请先选择 PCAP 文件';
        return;
    }
    const form = new FormData();
    form.append('file', input.files[0]);
    const button = document.getElementById('pcapParseBtn');
    button.disabled = true;
    status.textContent = '正在解析...';
    try {
        const response = await fetch('/api/pcap/import', { method: 'POST', body: form });
        const result = await response.json();
        if (!result.success) throw new Error(result.error || '解析失败');
        importedPcapPackets = result.packets;
        status.textContent = `${result.filename}：${result.packet_count} 条报文`;
        renderPcapPackets();
    } catch (error) {
        status.textContent = error.message;
        importedPcapPackets = [];
        renderPcapPackets();
    } finally {
        button.disabled = false;
    }
}

function renderPcapPackets() {
    const tbody = document.getElementById('pcapPacketList');
    tbody.innerHTML = '';
    if (!importedPcapPackets.length) {
        tbody.innerHTML = '<tr><td colspan="4" class="pcap-empty">未读取到报文</td></tr>';
        return;
    }
    importedPcapPackets.forEach(packet => {
        const row = document.createElement('tr');
        const index = document.createElement('td');
        index.textContent = packet.index + 1;
        const length = document.createElement('td');
        length.textContent = packet.length;
        const summary = document.createElement('td');
        summary.textContent = packet.summary;
        summary.title = packet.summary;
        const action = document.createElement('td');
        const button = document.createElement('button');
        button.className = 'mini-btn';
        button.textContent = '回填编辑';
        button.dataset.testid = `pcap-fill-${packet.index}`;
        button.onclick = () => fillPacketToEditor(packet.index);
        action.appendChild(button);
        row.append(index, length, summary, action);
        tbody.appendChild(row);
    });
}

function fillPacketToEditor(index) {
    const packet = importedPcapPackets.find(item => item.index === index);
    if (!packet || !packet.protocols.length) {
        showToast('该报文暂不支持字段回填');
        return;
    }
    selectedProtocols = [];
    packet.protocols.forEach(protocol => {
        if (!selectedProtocols.includes(protocol)) toggleProtocol(protocol);
    });
    renderValueInputs();
    renderFieldButtons();
    Object.entries(packet.fields).forEach(([protocol, values]) => {
        Object.entries(values).forEach(([field, value]) => {
            const input = document.getElementById(`legal-${protocol}-${field}`);
            if (input) input.value = value;
        });
    });
    selectedPcapPacket = packet;
    const ip = packet.fields.IP;
    if (ip) document.getElementById('targetIp').value = ip.dst;
    const transport = packet.fields.TCP || packet.fields.UDP;
    if (transport) document.getElementById('targetPort').value = transport.dstport;
    document.getElementById('sendModeSelect').value = 'raw';
    document.getElementById('sendModeSelect').dispatchEvent(new Event('change'));
    closePcapImport();
    addLog(`[PCAP] 已回填第 ${index + 1} 条报文：${packet.protocols.join(' -> ')}，可修改后发送或导出`);
}

function collectCurrentBuildRequest() {
    const illegalFields = Object.keys(fieldStates).filter(field => fieldStates[field] && !legalSendMode);
    const fields = {};
    const illegalFieldsMap = {};
    const illegalValuesMap = {};
    selectedProtocols.forEach(protocol => {
        const protocolIllegal = illegalFields.filter(field => field.startsWith(`${protocol}.`));
        fields[protocol] = buildPacketData(protocol, illegalFields);
        illegalFieldsMap[protocol] = protocolIllegal;
        illegalValuesMap[protocol] = {};
        protocolIllegal.forEach(field => {
            const short = field.startsWith(`${protocol}.`) ? field.slice(protocol.length + 1) : field;
            const input = document.getElementById(`illegal-${protocol}-${short}`);
            if (input) illegalValuesMap[protocol][field] = input.value;
        });
    });
    return {
        protocols: selectedProtocols,
        fields,
        illegal_fields_map: illegalFieldsMap,
        illegal_values_map: illegalValuesMap,
    };
}

async function exportCurrentPacket() {
    try {
        const request = collectCurrentBuildRequest();
        const buildResponse = await fetch('/api/scapy/build-multi', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(request),
        });
        const built = await buildResponse.json();
        if (!built.success) throw new Error(built.error || '报文构建失败');
        let packetHex = built.packet_hex;
        if (!built.packet_hex || request.protocols[0] !== 'ARP') {
            packetHex = `0000000000000000000000000800${built.packet_hex}`;
        }
        const response = await fetch('/api/pcap/export', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ packets: [packetHex], filename: `edited-${Date.now()}.pcap` }),
        });
        const result = await response.json();
        if (!result.success) throw new Error(result.error || '导出失败');
        const link = document.createElement('a');
        link.href = `/api/pcap/download/${encodeURIComponent(result.filename)}`;
        link.download = result.filename;
        link.click();
        addLog(`[PCAP] ✓ 当前编辑报文已导出：${result.filename}`);
    } catch (error) {
        addLog(`[PCAP] ✗ 导出失败 - ${error.message}`);
    }
}

function payloadByteLength(value) {
    const text = String(value || '').trim();
    if (!text) return 0;
    if (text.toLowerCase().startsWith('ascii:')) return new TextEncoder().encode(text.slice(6)).length;
    let hex = text.toLowerCase().startsWith('hex:') ? text.slice(4) : text;
    if (hex.toLowerCase().startsWith('0x')) hex = hex.slice(2);
    hex = hex.replace(/[\s,:-]/g, '');
    return /^[0-9a-f]*$/i.test(hex) && hex.length % 2 === 0 ? hex.length / 2 : new TextEncoder().encode(text).length;
}

document.addEventListener('input', event => {
    const input = event.target;
    if (input.dataset.field !== 'payload' || !input.id.startsWith('legal-')) return;
    const protocol = input.dataset.protocol;
    const lengthName = protocol === 'DOIP' ? 'payload_len' : protocol === 'IP' ? 'total_len' : 'length';
    const lengthInput = document.getElementById(`legal-${protocol}-${lengthName}`);
    if (!lengthInput) return;
    const payloadLength = payloadByteLength(input.value);
    if (protocol === 'SOMEIP' || protocol === 'SOMEIP-SD') lengthInput.value = payloadLength + 8;
    else if (protocol === 'UDP') lengthInput.value = payloadLength + 8;
    else lengthInput.value = payloadLength;
});
