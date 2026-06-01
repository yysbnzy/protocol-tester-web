function showCaptureDetail(packet) {
    const output = document.getElementById('captureOutput');
    if (!output) {
        console.error('[showCaptureDetail] captureOutput element not found');
        return;
    }
    if (!packet) {
        output.value = '选择捕获的报文查看详情';
        return;
    }
    
    const lines = [`=== ${packet.protocol || 'Unknown'} 报文 ===\n`];
    lines.push(`时间: ${packet.time || 'N/A'}`);
    lines.push(`长度: ${packet.length || 0} bytes`);
    lines.push(`协议: ${packet.protocol || 'Unknown'}\n`);
    
    if (packet.packet_hex) {
        lines.push('=== Raw Bytes (Hex) ===');
        lines.push(packet.packet_hex);
    }
    
    output.value = lines.join('\n');
}

// ===== 显示过滤器 =====
let currentDisplayFilter = '';
let currentDisplayFilterEngine = null;

function setDisplayFilter(filter) {
    const input = document.getElementById('displayFilterInput');
    if (input) {
        input.value = filter;
        applyDisplayFilter();
    }
}

function applyDisplayFilter() {
    const input = document.getElementById('displayFilterInput');
    const status = document.getElementById('displayFilterStatus');
    if (!input) return;
    
    currentDisplayFilter = input.value.trim();
    
    if (!currentDisplayFilter) {
        currentDisplayFilterEngine = null;
        if (status) status.textContent = '';
        // 重新渲染所有报文
        renderAllCapturePackets();
        return;
    }
    
    // 前端使用简单过滤（更复杂的用后端过滤）
    // 对于复杂表达式，调用后端过滤
    if (currentDisplayFilter.includes('==') || currentDisplayFilter.includes('!=') || 
        currentDisplayFilter.includes('>') || currentDisplayFilter.includes('<') ||
        currentDisplayFilter.includes('in')) {
        // 后端过滤
        if (status) status.textContent = '使用后端过滤...';
        applyBackendFilter();
    } else {
        // 前端简单过滤（协议名）
        if (status) status.textContent = `前端过滤: ${currentDisplayFilter}`;
        renderAllCapturePackets();
    }
}

function clearDisplayFilter() {
    const input = document.getElementById('displayFilterInput');
    const status = document.getElementById('displayFilterStatus');
    if (input) input.value = '';
    if (status) status.textContent = '';
    currentDisplayFilter = '';
    currentDisplayFilterEngine = null;
    renderAllCapturePackets();
}

function applyBackendFilter() {
    // 调用后端过滤 API
    fetch('/api/capture/filter/apply', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ filter: currentDisplayFilter })
    })
    .then(r => r.json())
    .then(result => {
        const status = document.getElementById('displayFilterStatus');
        if (result.success) {
            const filtered = result.filtered_packets || [];
            if (status) status.textContent = `后端过滤: ${result.matched || filtered.length} / ${result.total || capturedPackets.length} 匹配`;
            renderFilteredPackets(filtered);
        } else {
            if (status) status.textContent = `过滤错误: ${result.message || 'Unknown'}`;
            // 回退到前端过滤
            renderAllCapturePackets();
        }
    })
    .catch(err => {
        const status = document.getElementById('displayFilterStatus');
        if (status) status.textContent = `后端过滤失败: ${err.message}`;
        renderAllCapturePackets();
    });
}

function renderAllCapturePackets() {
    const tbody = document.getElementById('captureTableBody');
    if (!tbody) return;
    
    if (!capturedPackets || capturedPackets.length === 0) {
        tbody.innerHTML = `<tr class="empty-row"><td colspan="13" style="text-align: center; color: #999; padding: 40px;">点击"开始捕获"按钮开始抓包...</td></tr>`;
        return;
    }
    
    tbody.innerHTML = '';
    let foreignCount = 0;
    
    capturedPackets.forEach((pkt, index) => {
        const pktNum = index + 1;
        
        // 前端过滤检查
        if (currentDisplayFilter && !frontendFilterMatch(pkt, currentDisplayFilter)) {
            return;
        }
        
        if (pkt.is_foreign) foreignCount++;
        
        const rowClass = getProtocolColorClass(pkt.protocol) + (pkt.is_foreign ? ' foreign-packet' : '');
        const srcMacShort = pkt.src_mac && pkt.src_mac !== '-' ? pkt.src_mac : '-';
        const dstMacShort = pkt.dst_mac && pkt.dst_mac !== '-' ? pkt.dst_mac : '-';
        
        const tr = document.createElement('tr');
        tr.className = rowClass;
        tr.onclick = () => showPacketDetail(pkt.id);
        tr.dataset.packetId = pkt.id;
        tr.innerHTML = `
            <td style="text-align: right;">${pktNum}</td>
            <td>${formatTime(pkt)}</td>
            <td>${pkt.src_ip || '-'}</td>
            <td>${pkt.dst_ip || '-'}</td>
            <td>${srcMacShort}</td>
            <td>${dstMacShort}</td>
            <td>${pkt.src_port || '-'}</td>
            <td>${pkt.dst_port || '-'}</td>
            <td class="protocol-cell">${pkt.protocol || '-'}</td>
            <td class="info-col" title="${pkt.info || '-'}">${pkt.info || '-'}</td>
            <td>${pkt.length || 0}</td>
            <td class="crl-col" title="${pkt.raw_bytes || '-'}">${pkt.raw_bytes || '-'}</td>
            <td>${pkt.country || '-'}</td>
        `;
        tbody.appendChild(tr);
    });
    
    document.getElementById('totalPackets').textContent = capturedPackets.length;
    document.getElementById('foreignPackets').textContent = foreignCount;
}

function renderFilteredPackets(filteredPackets) {
    const tbody = document.getElementById('captureTableBody');
    if (!tbody) return;
    
    tbody.innerHTML = '';
    let foreignCount = 0;
    
    filteredPackets.forEach((pkt, index) => {
        if (pkt.is_foreign) foreignCount++;
        
        const rowClass = getProtocolColorClass(pkt.protocol) + (pkt.is_foreign ? ' foreign-packet' : '');
        const srcMacShort = pkt.src_mac && pkt.src_mac !== '-' ? pkt.src_mac : '-';
        const dstMacShort = pkt.dst_mac && pkt.dst_mac !== '-' ? pkt.dst_mac : '-';
        
        const tr = document.createElement('tr');
        tr.className = rowClass;
        tr.onclick = () => showPacketDetail(pkt.id);
        tr.dataset.packetId = pkt.id;
        tr.innerHTML = `
            <td style="text-align: right;">${index + 1}</td>
            <td>${formatTime(pkt)}</td>
            <td>${pkt.src_ip || '-'}</td>
            <td>${pkt.dst_ip || '-'}</td>
            <td>${srcMacShort}</td>
            <td>${dstMacShort}</td>
            <td>${pkt.src_port || '-'}</td>
            <td>${pkt.dst_port || '-'}</td>
            <td class="protocol-cell">${pkt.protocol || '-'}</td>
            <td class="info-col" title="${pkt.info || '-'}">${pkt.info || '-'}</td>
            <td>${pkt.length || 0}</td>
            <td class="crl-col" title="${pkt.raw_bytes || '-'}">${pkt.raw_bytes || '-'}</td>
            <td>${pkt.country || '-'}</td>
        `;
        tbody.appendChild(tr);
    });
    
    document.getElementById('totalPackets').textContent = filteredPackets.length;
    document.getElementById('foreignPackets').textContent = foreignCount;
}

function frontendFilterMatch(pkt, filter) {
    // 简单前端过滤：协议名、IP、端口
    const f = filter.toLowerCase().trim();
    
    // 协议名匹配
    if (f === 'tcp') return pkt.protocol === 'TCP';
    if (f === 'udp') return pkt.protocol === 'UDP';
    if (f === 'icmp') return pkt.protocol === 'ICMP';
    if (f === 'arp') return pkt.protocol === 'ARP';
    if (f === 'doip') return pkt.protocol === 'DOIP';
    if (f === 'someip') return pkt.protocol === 'SOMEIP' || pkt.protocol === 'SOMEIP-SD';
    if (f === 'someip-sd') return pkt.protocol === 'SOMEIP-SD';
    if (f === 'http') return pkt.protocol === 'HTTP' || (pkt.src_port == 80 || pkt.dst_port == 80 || pkt.src_port == 8080 || pkt.dst_port == 8080);
    if (f === 'https') return pkt.protocol === 'HTTPS' || (pkt.src_port == 443 || pkt.dst_port == 443);
    if (f === 'dns') return pkt.protocol === 'DNS' || (pkt.src_port == 53 || pkt.dst_port == 53);
    if (f === 'ssh') return pkt.protocol === 'SSH' || (pkt.src_port == 22 || pkt.dst_port == 22);
    if (f === 'ftp') return pkt.protocol === 'FTP' || (pkt.src_port == 21 || pkt.dst_port == 21);
    if (f === 'dhcp') return pkt.protocol === 'DHCP' || (pkt.src_port == 67 || pkt.dst_port == 67 || pkt.src_port == 68 || pkt.dst_port == 68);
    
    // 简单包含匹配
    return (pkt.protocol || '').toLowerCase().includes(f) ||
           (pkt.src_ip || '').includes(f) ||
           (pkt.dst_ip || '').includes(f) ||
           (pkt.info || '').toLowerCase().includes(f);
}

// ===== 协议着色 =====
function getProtocolColorClass(protocol) {
    if (!protocol) return '';
    const p = protocol.toLowerCase();
    if (p === 'tcp') return 'pkt-tcp';
    if (p === 'udp') return 'pkt-udp';
    if (p === 'icmp') return 'pkt-icmp';
    if (p === 'arp') return 'pkt-arp';
    if (p === 'doip') return 'pkt-doip';
    if (p === 'someip' || p === 'someip-sd') return 'pkt-someip';
    if (p === 'http' || p === 'https') return 'pkt-http';
    if (p === 'dns') return 'pkt-dns';
    if (p === 'ssh') return 'pkt-ssh';
    if (p === 'ftp') return 'pkt-ftp';
    if (p === 'dhcp') return 'pkt-dhcp';
    return '';
}

// ===== 时间显示格式 =====
let timeFormat = 'relative'; // 'relative' | 'absolute' | 'delta'
let firstTimestamp = null;
let lastTimestamp = null;

function formatTime(pkt) {
    if (!pkt || !pkt.time) return '-';
    
    const ts = pkt.timestamp || parseWiresharkTime(pkt.time);
    if (ts === null || ts === undefined) return pkt.time;
    
    if (timeFormat === 'absolute') {
        const d = new Date(ts * 1000);
        return d.toISOString().replace('T', ' ').substring(0, 23);
    }
    
    if (timeFormat === 'delta') {
        if (lastTimestamp === null) {
            lastTimestamp = ts;
            return '0.000000';
        }
        const delta = ts - lastTimestamp;
        lastTimestamp = ts;
        return delta.toFixed(6);
    }
    
    // relative (默认)
    if (firstTimestamp === null) {
        firstTimestamp = ts;
        return '0.000000';
    }
    const rel = ts - firstTimestamp;
    return rel.toFixed(6);
}

function parseWiresharkTime(timeStr) {
    if (!timeStr) return null;
    // 尝试解析 "0.000000" 格式（相对时间字符串）
    const m = timeStr.match(/^([0-9.]+)$/);
    if (m) return parseFloat(m[1]);
    // 尝试解析时间戳
    const d = new Date(timeStr);
    if (!isNaN(d.getTime())) return d.getTime() / 1000;
    return null;
}

function setTimeFormat(format) {
    timeFormat = format;
    // 重置时间基准
    firstTimestamp = null;
    lastTimestamp = null;
    // 重新渲染
    renderAllCapturePackets();
    // 更新按钮状态
    document.querySelectorAll('.time-format-btn').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.format === format);
    });
}

        
        async function toggleCapture() {
            const btn = document.getElementById('captureToggleBtn');
            const nicSelect = document.getElementById('nicSelect');
            const refreshBtn = document.querySelector('.refresh-btn');
            const nic = nicSelect.value;
            
            if (!captureRunning) {
                // 开始捕获前，先清空之前的报文（Wireshark风格）
                capturedPackets = [];
                document.getElementById('captureTableBody').innerHTML = `
                    <tr class="empty-row">
                        <td colspan="13" style="text-align: center; color: #999; padding: 40px;">
                            正在捕获报文...
                        </td>
                    </tr>
                `;
                document.getElementById('totalPackets').textContent = '0';
                document.getElementById('foreignPackets').textContent = '0';
                
                // 强制停止之前的捕获（防止状态不一致）
                try {
                    await fetch('/api/capture/stop', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ force: true })
                    });
                } catch (e) {
                    // 忽略错误
                }
                
                // 开始捕获
                try {
                    addLog(`[捕获] 正在启动... 网卡: ${nic}`);
                    const response = await fetch('/api/capture/start', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            interface: nic,
                            protocols: ['TCP', 'UDP', 'ICMP', 'ARP']
                        })
                    });
                    
                    const result = await response.json();
                    
                    if (result.success) {
                        captureRunning = true;
                        btn.textContent = '停止捕获';
                        btn.style.background = '#f44336';
                        addLog(`[捕获] ✓ 已开始 - ${result.message || '正在抓取报文'}`);
                        
                        // 启动轮询获取报文
                        startCapturePolling();
                    } else {
                        addLog(`[捕获] ✗ 启动失败 - ${result.message}`);
                    }
                } catch (error) {
                    addLog(`[捕获] ✗ 错误 - ${error.message}`);
                }
            } else {
                // 停止捕获
                try {
                    addLog('[捕获] 正在停止...');
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ force: true })
                    });
                    
                    // 检查响应类型
                    const contentType = response.headers.get('content-type');
                    if (!contentType || !contentType.includes('application/json')) {
                        // 后端返回错误页面，强制重置状态
                        captureRunning = false;
                        btn.textContent = '开始捕获';
                        btn.style.background = '#2196f3';
                        stopCapturePolling();
                        addLog('[捕获] ✓ 已停止（强制）');
                        return;
                    }
                    
                    
                    if (result.success) {
                        captureRunning = false;
                        btn.textContent = '开始捕获';
                        btn.style.background = '#2196f3';
                        addLog(`[捕获] ✓ 已停止 - 共捕获 ${result.total_packets || 0} 个报文`);
                        stopCapturePolling();
                    } else {
                        addLog(`[捕获] ✗ 停止失败 - ${result.message}`);
                    }
                } catch (error) {
                    // 出错时强制重置状态
                    captureRunning = false;
                    btn.textContent = '开始捕获';
                    btn.style.background = '#2196f3';
                    stopCapturePolling();
                    addLog('[捕获] ✓ 已停止（异常恢复）');
                }
            }
        }
        
        // 轮询获取捕获的报文
        function startCapturePolling() {
            // 立即获取一次
            fetchCapturedPackets();
            
            // 每500ms轮询一次
            capturePollInterval = setInterval(fetchCapturedPackets, 500);
        }
        
        function stopCapturePolling() {
            if (capturePollInterval) {
                clearInterval(capturePollInterval);
                capturePollInterval = null;
            }
        }
        
        // 获取捕获的报文
        async function fetchCapturedPackets() {
            try {
                
                // 检查响应是否是JSON
                if (!contentType || !contentType.includes('application/json')) {
                    // 不是JSON，可能是错误页面，忽略
                    return;
                }
                
                
                if (result.success && result.packets) {
                    // Wireshark风格：增量更新，只添加新报文
                    const newPackets = result.packets.slice(capturedPackets.length);
                    if (newPackets.length > 0) {
                        capturedPackets = result.packets;
                        appendCaptureList(newPackets, capturedPackets.length);
                        document.getElementById('totalPackets').textContent = capturedPackets.length;
                    }
                }
            } catch (error) {
                // 静默处理错误，不显示在控制台
            }
        }
        
        // 更新捕获列表显示
        function updateCaptureList(packets) {
            const tbody = document.getElementById('captureTableBody');
            
            if (!packets || packets.length === 0) {
                tbody.innerHTML = `
                    <tr class="empty-row">
                        <td colspan="13" style="text-align: center; color: #999; padding: 40px;">
                            点击"开始捕获"按钮开始抓包...
                        </td>
                    </tr>
                `;
                return;
            }
            
            let html = '';
            let foreignCount = 0;
            
            packets.slice(-50).reverse().forEach((pkt, index) => {
                const pktNum = packets.length - index;
                const colorClass = getProtocolColorClass(pkt.protocol);
                const rowClass = colorClass + (pkt.is_foreign ? ' foreign-packet' : '');
                if (pkt.is_foreign) foreignCount++;
                
                // 完整MAC地址显示
                const srcMacShort = pkt.src_mac && pkt.src_mac !== '-' ? pkt.src_mac : '-';
                const dstMacShort = pkt.dst_mac && pkt.dst_mac !== '-' ? pkt.dst_mac : '-';
                
                html += `<tr class="${rowClass}" onclick="showPacketDetail('${pkt.id}')">`;
                html += `<td style="text-align: right;">${pktNum}</td>`;
                html += `<td>${formatTime(pkt)}</td>`;
                html += `<td>${pkt.src_ip || '-'}</td>`;
                html += `<td>${pkt.dst_ip || '-'}</td>`;
                html += `<td>${srcMacShort}</td>`;
                html += `<td>${dstMacShort}</td>`;
                html += `<td>${pkt.src_port || '-'}</td>`;
                html += `<td>${pkt.dst_port || '-'}</td>`;
                html += `<td class="protocol-cell">${pkt.protocol || '-'}</td>`;
                html += `<td class="info-col" title="${pkt.info || '-'}">${pkt.info || '-'}</td>`;
                html += `<td>${pkt.length || 0}</td>`;
                html += `<td class="crl-col" title="${pkt.raw_bytes || '-'}">${pkt.raw_bytes || '-'}</td>`;
                html += `<td>${pkt.country || '-'}</td>`;
                html += '</tr>';
            });
            
            tbody.innerHTML = html;
            
            // 更新统计
            document.getElementById('totalPackets').textContent = packets.length;
            document.getElementById('foreignPackets').textContent = foreignCount;
        }
        
        // 追加新报文到表格（Wireshark风格 - 实时追加）
        function appendCaptureList(newPackets, totalCount) {
            const container = document.querySelector('.capture-table-container');
            
            // 获取当前滚动位置和是否滚动到底部
            const isScrolledToBottom = container.scrollHeight - container.scrollTop - container.clientHeight < 50;
            
            // 如果是空表格，清除空行提示
            if (tbody.querySelector('.empty-row')) {
                tbody.innerHTML = '';
            }
            
            // 限制表格总行数（性能考虑），超过时移除旧行
            const maxRows = 500;
            const currentRows = tbody.querySelectorAll('tr:not(.empty-row)');
            const rowsToRemove = currentRows.length + newPackets.length - maxRows;
            if (rowsToRemove > 0) {
                for (let i = 0; i < rowsToRemove; i++) {
                    if (currentRows[i]) currentRows[i].remove();
                }
            }
            
            // 添加新行
            
            newPackets.forEach((pkt, index) => {
                if (pkt.is_foreign) foreignCount++;
                
                const colorClass = getProtocolColorClass(pkt.protocol);
                const rowClass = colorClass + (pkt.is_foreign ? ' foreign-packet' : '');
                const pktNum = totalCount - newPackets.length + index + 1;
                
                const srcMacShort = pkt.src_mac && pkt.src_mac !== '-' ? pkt.src_mac : '-';
                const dstMacShort = pkt.dst_mac && pkt.dst_mac !== '-' ? pkt.dst_mac : '-';
                
                const row = document.createElement('tr');
                row.className = rowClass;
                row.onclick = () => showPacketDetail(pkt.id);
                row.dataset.packetId = pkt.id;
                
                row.innerHTML = `
                    <td style="text-align: right;">${pktNum}</td>
                    <td>${formatTime(pkt)}</td>
                    <td>${pkt.src_ip || '-'}</td>
                    <td>${pkt.dst_ip || '-'}</td>
                    <td>${srcMacShort}</td>
                    <td>${dstMacShort}</td>
                    <td>${pkt.src_port || '-'}</td>
                    <td>${pkt.dst_port || '-'}</td>
                    <td class="protocol-cell">${pkt.protocol || '-'}</td>
                    <td class="info-col" title="${pkt.info || '-'}">${pkt.info || '-'}</td>
                    <td>${pkt.length || 0}</td>
                    <td class="crl-col" title="${pkt.raw_bytes || '-'}">${pkt.raw_bytes || '-'}</td>
                    <td>${pkt.country || '-'}</td>
                `;
                
                // 追加到表格末尾（Wireshark风格：新报文在底部）
                tbody.appendChild(row);
            });
            
            // 更新统计
            document.getElementById('foreignPackets').textContent = foreignCount;
            
            // 如果之前在底部，自动滚动到新报文
            if (isScrolledToBottom) {
                container.scrollTop = container.scrollHeight;
            }
        }
        
        // 清空捕获列表
        async function clearCapture() {
            try {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' }
                });
                
                
                if (result.success) {
                    capturedPackets = [];
                    document.getElementById('captureTableBody').innerHTML = `
                        <tr class="empty-row">
                            <td colspan="13" style="text-align: center; color: #999; padding: 40px;">
                                点击"开始捕获"按钮开始抓包...
                            </td>
                        </tr>
                    `;
                    document.getElementById('totalPackets').textContent = '0';
                    document.getElementById('foreignPackets').textContent = '0';
                    addLog('[捕获] ✓ 已清空');
                } else {
                    addLog(`[捕获] ✗ 清空失败 - ${result.message}`);
                }
            } catch (error) {
                addLog(`[捕获] ✗ 错误 - ${error.message}`);
            }
        }
        
        // 导出PCAP
        async function startCapture() {
            const protocols = [];
            if (document.getElementById('filterTCP').checked) protocols.push('TCP');
            if (document.getElementById('filterUDP').checked) protocols.push('UDP');
            if (document.getElementById('filterICMP').checked) protocols.push('ICMP');
            if (document.getElementById('filterARP').checked) protocols.push('ARP');
            
            addLog(`[捕获] 正在启动... 网卡: ${nic}`);
            
            try {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        interface: nic,
                        protocols: protocols
                    })
                });
                
                
                if (result.success) {
                    captureRunning = true;
                    document.getElementById('startCaptureBtn').style.display = 'none';
                    document.getElementById('stopCaptureBtn').style.display = 'block';
                    document.getElementById('captureStatus').textContent = '🔴 捕获中';
                    // 捕获开始时禁用网卡选择
                    nicSelect.disabled = true;
                    if (refreshBtn) refreshBtn.disabled = true;
                    nicSelect.style.background = '#e0e0e0';
                    nicSelect.style.cursor = 'not-allowed';
                    addLog(`[捕获] ✓ 已开始`);
                    startCapturePolling();
                } else {
                    addLog(`[捕获] ✗ 启动失败 - ${result.message}`);
                }
            } catch (error) {
                addLog(`[捕获] ✗ 错误 - ${error.message}`);
            }
        }
        
        async function stopCapture() {
            addLog('[捕获] 正在停止...');
            
            try {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ force: true })
                });
                
                
                if (result.success) {
                    captureRunning = false;
                    document.getElementById('startCaptureBtn').style.display = 'block';
                    document.getElementById('stopCaptureBtn').style.display = 'none';
                    document.getElementById('captureStatus').textContent = '⏹️ 停止';
                    // 捕获停止时启用网卡选择
                    nicSelect.disabled = false;
                    if (refreshBtn) refreshBtn.disabled = false;
                    nicSelect.style.background = '';
                    nicSelect.style.cursor = '';
                    addLog(`[捕获] ✓ 已停止 - 共捕获 ${result.total_packets || 0} 个报文`);
                    stopCapturePolling();
                } else {
                    addLog(`[捕获] ✗ 停止失败 - ${result.message}`);
                }
            } catch (error) {
                captureRunning = false;
                document.getElementById('startCaptureBtn').style.display = 'block';
                document.getElementById('stopCaptureBtn').style.display = 'none';
                document.getElementById('captureStatus').textContent = '⏹️ 停止';
                // 捕获停止时启用网卡选择（异常恢复）
                nicSelect.disabled = false;
                if (refreshBtn) refreshBtn.disabled = false;
                nicSelect.style.background = '';
                nicSelect.style.cursor = '';
                stopCapturePolling();
                addLog('[捕获] ✓ 已停止');
            }
        }
        
        let currentSelectedPacket = null;
        let currentDetailTab = 'layers';
        let selectedFieldId = null;  // 当前选中的字段ID

        // 双向映射核心函数：协议层级 → Hex
        function switchDetailTab(tab) {
            currentDetailTab = tab;
            document.querySelectorAll('.packet-detail-tab').forEach(btn => {
                btn.classList.remove('active');
            });
            event.target.classList.add('active');
            
            // 重新渲染当前报文
            if (currentSelectedPacket) {
                renderPacketDetail(currentSelectedPacket);
            }
        }

        // 显示报文详情（新版 - Wireshark风格）
        function showPacketDetail(packetId) {
            console.log('[DEBUG] showPacketDetail called with packetId:', packetId);
            console.log('[DEBUG] capturedPackets:', capturedPackets.length);
            
            const pkt = capturedPackets.find(p => p.id === packetId);
            if (!pkt) {
                console.error('[showPacketDetail] Packet not found:', packetId);
                return;
            }
            
            console.log('[DEBUG] Found packet:', pkt);
            currentSelectedPacket = pkt;
            
            // 更新标题
            document.getElementById('packetDetailTitle').textContent = 
                `#${pkt.id ? pkt.id.replace('pkt_', '') : '1'} ${pkt.protocol || 'Unknown'} ${pkt.length || 0} bytes on ${pkt.time || '0.000000'}`;
            
            // 渲染详情
            renderPacketDetail(pkt);
            
            // 高亮表格中的选中行
            document.querySelectorAll('#captureTableBody tr').forEach(row => {
                row.style.background = '';
                if (row.dataset.packetId === packetId) {
                    row.style.background = '#bbdefb';
                }
            });
        }

        // 渲染报文详情
        function renderPacketDetail(pkt) {
            // 解析 raw_bytes
            const rawBytes = pkt.raw_bytes || '';
            
            if (currentDetailTab === 'layers') {
                renderPacketLayers(pkt, rawBytes);
            } else {
                renderPacketHex(rawBytes);
            }
        }

        // 渲染协议层级树 - Wireshark 风格
        function renderPacketLayers(pkt, rawBytes) {
            const panel = document.getElementById('packetTreePanel');
            
            const bytesLen = rawBytes.length / 2;
            
            // === Frame 层级 ===
            html += `<div class="packet-tree-item packet-tree-l1 proto-frame" data-field-id="frame">`;
            html += `<span class="packet-tree-expand">▼</span>Frame ${pkt.id ? pkt.id.replace('pkt_', '') : '1'}: ${bytesLen} bytes on interface`;
            html += `</div>`;
            html += `<div class="packet-tree-item packet-tree-l2" data-field-id="frame.time">Arrival Time: ${pkt.time || '0.000000'}</div>`;
            html += `<div class="packet-tree-item packet-tree-l2" data-field-id="frame.len">Frame Length: ${bytesLen} bytes (${bytesLen * 8} bits)</div>`;
            html += `<div class="packet-tree-item packet-tree-l2" data-field-id="frame.protocol">Protocols in frame: ${getProtocolsInFrame(pkt)}</div>`;
            
            // === Ethernet II 层级 ===
            if (pkt.src_mac && pkt.src_mac !== '-') {
                const ethType = getEthernetType(pkt.protocol);
                html += `<div class="packet-tree-item packet-tree-l1 proto-ethernet" data-field-id="eth">`;
                html += `<span class="packet-tree-expand">▼</span>Ethernet II, Src: ${formatMac(pkt.src_mac)}, Dst: ${formatMac(pkt.dst_mac)}`;
                html += `</div>`;
                html += `<div class="packet-tree-item packet-tree-l2" data-field-id="dst_mac">Destination: ${formatMac(pkt.dst_mac)}</div>`;
                html += `<div class="packet-tree-item packet-tree-l2" data-field-id="src_mac">Source: ${formatMac(pkt.src_mac)}</div>`;
                html += `<div class="packet-tree-item packet-tree-l2" data-field-id="ethertype">Type: ${ethType} (0x${getEtherTypeHex(pkt.protocol)})</div>`;
            }
            
            // === IP 层级 ===
            // 检测是否有 IP 层（通过 src_ip 或 raw_bytes 中的版本字段）
            const hasIP = pkt.src_ip && pkt.src_ip !== '-' || pkt.dst_ip && pkt.dst_ip !== '-' || 
                         (rawBytes.length >= 28 && rawBytes.substring(24, 26) === '08');  // IPv4 ethertype
            
            if (hasIP) {
                const ipProto = getIPProtocolName(pkt.protocol);
                html += `<div class="packet-tree-item packet-tree-l1 proto-ip" data-field-id="ip">`;
                html += `<span class="packet-tree-expand">▼</span>Internet Protocol Version 4, Src: ${pkt.src_ip || '0.0.0.0'}, Dst: ${pkt.dst_ip || '0.0.0.0'}`;
                html += `</div>`;
                html += `<div class="packet-tree-item packet-tree-l2" data-field-id="version_ihl">0100 .... = Version: 4</div>`;
                html += `<div class="packet-tree-item packet-tree-l2" data-field-id="tos">.... 0101 = Header Length: 20 bytes (5)</div>`;
                html += `<div class="packet-tree-item packet-tree-l2" data-field-id="tos">Differentiated Services Field: 0x00</div>`;
                html += `<div class="packet-tree-item packet-tree-l2" data-field-id="total_len">Total Length: ${bytesLen}</div>`;
                html += `<div class="packet-tree-item packet-tree-l2" data-field-id="id">Identification: 0x0000</div>`;
                html += `<div class="packet-tree-item packet-tree-l2" data-field-id="flags_frag">Flags: 0x0000</div>`;
                html += `<div class="packet-tree-item packet-tree-l2" data-field-id="ttl">Time to live: 64</div>`;
                html += `<div class="packet-tree-item packet-tree-l2" data-field-id="protocol">Protocol: ${ipProto} (${getIPProtocolNum(pkt.protocol)})</div>`;
                html += `<div class="packet-tree-item packet-tree-l2" data-field-id="checksum">Header checksum: 0x0000</div>`;
                html += `<div class="packet-tree-item packet-tree-l2" data-field-id="src_ip">Source: ${pkt.src_ip || '0.0.0.0'}</div>`;
                html += `<div class="packet-tree-item packet-tree-l2" data-field-id="dst_ip">Destination: ${pkt.dst_ip || '0.0.0.0'}</div>`;
            }
            
            // === 传输层协议 ===
            // TCP
            if (pkt.protocol === 'TCP' || pkt.src_port !== '-' || pkt.dst_port !== '-') {
                console.log('[DEBUG] Rendering TCP layer, pkt:', pkt);
                // 使用后端提供的 Data Offset 和 Options
                const dataOffset = pkt.tcp_data_offset || 5;
                const headerLen = dataOffset * 4;  // Data Offset 是以 4 字节为单位的
                const optionsLen = headerLen - 20;  // 减去固定的 20 字节头部
                const tcpOptions = pkt.tcp_options || [];
                
                html += `<div class="packet-tree-item packet-tree-l1 proto-tcp" data-field-id="tcp">`;
                html += `<span class="packet-tree-expand">▼</span>Transmission Control Protocol, Src Port: ${pkt.src_port || '?'}, Dst Port: ${pkt.dst_port || '?'}`;
                html += `</div>`;
                html += `<div class="packet-tree-item packet-tree-l2" data-field-id="src_port">Source Port: ${pkt.src_port || '-'}</div>`;
                html += `<div class="packet-tree-item packet-tree-l2" data-field-id="dst_port">Destination Port: ${pkt.dst_port || '-'}</div>`;
                html += `<div class="packet-tree-item packet-tree-l2" data-field-id="seq">Sequence number: 0</div>`;
                html += `<div class="packet-tree-item packet-tree-l2" data-field-id="ack">Acknowledgment number: 0</div>`;
                html += `<div class="packet-tree-item packet-tree-l2" data-field-id="data_offset">Header Length: ${headerLen} bytes (${dataOffset} * 4)</div>`;
                html += `<div class="packet-tree-item packet-tree-l2" data-field-id="flags">Flags: 0x000</div>`;
                html += `<div class="packet-tree-item packet-tree-l2" data-field-id="window">Window size value: 65535</div>`;
                html += `<div class="packet-tree-item packet-tree-l2" data-field-id="checksum">Checksum: 0x0000</div>`;
                html += `<div class="packet-tree-item packet-tree-l2" data-field-id="urgent">Urgent pointer: 0</div>`;
                
                // 显示 Options 字段
                if (tcpOptions.length > 0) {
                    const optionsId = 'tcp_options_' + pkt.id;
                    html += `<div class="packet-tree-item packet-tree-l2" data-field-id="options" onclick="toggleExpand('${optionsId}', this.querySelector('.packet-tree-expand'))">`;
                    html += `<span class="packet-tree-expand">▼</span>Options: (${optionsLen} bytes)`;
                    html += `</div>`;
                    html += `<div id="${optionsId}" class="packet-tree-children">`;
                    
                    // 显示解析后的 Options，计算每个 Option 的偏移量
                    let currentOffset = 54; // Options 从 TCP 头部第 54 字节开始
                    tcpOptions.forEach((opt, idx) => {
                        const optValue = opt.value ? `: ${opt.value}` : '';
                        // 计算 Option 长度
                        let optLen = 1; // Kind 至少 1 字节
                        if (opt.kind === 0) {
                            optLen = 1; // EOL
                        } else if (opt.kind === 1) {
                            optLen = 1; // NOP
                        } else {
                            // 其他选项有 Length 字段，从后端获取或使用默认值
                            optLen = opt.length || 2; // 默认 Kind + Length
                            if (opt.kind === 2) optLen = 4; // MSS
                            else if (opt.kind === 3) optLen = 3; // Window Scale
                            else if (opt.kind === 4) optLen = 2; // SACK Permitted
                            else if (opt.kind === 8) optLen = 10; // Timestamps
                        }
                        
                        html += `<div class="packet-tree-item packet-tree-l3" data-field-id="opt_${opt.kind}_${idx}" data-offset="${currentOffset}" data-length="${optLen}">${opt.name}${optValue}</div>`;
                        currentOffset += optLen;
                    });
                    html += `</div>`;
                } else if (optionsLen > 0) {
                    html += `<div class="packet-tree-item packet-tree-l2" data-field-id="options">`;
                    html += `<span class="packet-tree-expand">▼</span>Options: (${optionsLen} bytes, raw data)`;
                    html += `</div>`;
                } else {
                    html += `<div class="packet-tree-item packet-tree-l2" data-field-id="options">Options: None</div>`;
                }
            } else if (pkt.protocol === 'UDP' && pkt.src_port && pkt.src_port !== '-') {
                html += `<div class="packet-tree-item packet-tree-l1 proto-udp" data-field-id="udp">`;
                html += `<span class="packet-tree-expand">▼</span>User Datagram Protocol, Src Port: ${pkt.src_port}, Dst Port: ${pkt.dst_port}`;
                html += `</div>`;
                html += `<div class="packet-tree-item packet-tree-l2" data-field-id="src_port">Source Port: ${pkt.src_port}</div>`;
                html += `<div class="packet-tree-item packet-tree-l2" data-field-id="dst_port">Destination Port: ${pkt.dst_port}</div>`;
                html += `<div class="packet-tree-item packet-tree-l2" data-field-id="length">Length: ${bytesLen - 34}</div>`;
                html += `<div class="packet-tree-item packet-tree-l2" data-field-id="checksum">Checksum: 0x0000</div>`;
            } else if (pkt.protocol === 'ICMP') {
                html += `<div class="packet-tree-item packet-tree-l1 proto-icmp" data-field-id="icmp">`;
                html += `<span class="packet-tree-expand">▼</span>Internet Control Message Protocol</div>`;
                html += `<div class="packet-tree-item packet-tree-l2" data-field-id="type">Type: 8 (Echo (ping) request)</div>`;
                html += `<div class="packet-tree-item packet-tree-l2" data-field-id="code">Code: 0</div>`;
                html += `<div class="packet-tree-item packet-tree-l2" data-field-id="checksum">Checksum: 0x0000</div>`;
                html += `<div class="packet-tree-item packet-tree-l2" data-field-id="id">Identifier: 0x0001</div>`;
                html += `<div class="packet-tree-item packet-tree-l2" data-field-id="seq">Sequence number: 1</div>`;
            } else if (pkt.protocol === 'ARP') {
                html += `<div class="packet-tree-item packet-tree-l1 proto-arp" data-field-id="arp">`;
                html += `<span class="packet-tree-expand">▼</span>Address Resolution Protocol (${pkt.info || 'request'})</div>`;
                html += `<div class="packet-tree-item packet-tree-l2" data-field-id="hw_type">Hardware type: Ethernet (1)</div>`;
                html += `<div class="packet-tree-item packet-tree-l2" data-field-id="proto_type">Protocol type: IPv4 (0x0800)</div>`;
                html += `<div class="packet-tree-item packet-tree-l2" data-field-id="hw_size">Hardware size: 6</div>`;
                html += `<div class="packet-tree-item packet-tree-l2" data-field-id="proto_size">Protocol size: 4</div>`;
                html += `<div class="packet-tree-item packet-tree-l2" data-field-id="opcode">Opcode: request (1)</div>`;
                html += `<div class="packet-tree-item packet-tree-l2" data-field-id="src_mac">Sender MAC address: ${pkt.src_mac || '00:00:00:00:00:00'}</div>`;
                html += `<div class="packet-tree-item packet-tree-l2" data-field-id="src_ip">Sender IP address: ${pkt.src_ip || '0.0.0.0'}</div>`;
                html += `<div class="packet-tree-item packet-tree-l2" data-field-id="dst_mac">Target MAC address: ${pkt.dst_mac || '00:00:00:00:00:00'}</div>`;
                html += `<div class="packet-tree-item packet-tree-l2" data-field-id="dst_ip">Target IP address: ${pkt.dst_ip || '0.0.0.0'}</div>`;
            } else if (pkt.protocol === 'SOMEIP' || pkt.protocol === 'SOMEIP-SD') {
                const isSD = pkt.protocol === 'SOMEIP-SD';
                html += `<div class="packet-tree-item packet-tree-l1 proto-someip" data-field-id="someip">`;
                html += `<span class="packet-tree-expand">▼</span>Scalable service-Oriented Middleware over IP${isSD ? ' (Service Discovery)' : ''}`;
                html += `</div>`;
                html += `<div class="packet-tree-item packet-tree-l2" data-field-id="service">Service ID: 0x1234</div>`;
                html += `<div class="packet-tree-item packet-tree-l2" data-field-id="method">Method ID: 0x5678</div>`;
                html += `<div class="packet-tree-item packet-tree-l2" data-field-id="length">Length: ${bytesLen - 42}</div>`;
                html += `<div class="packet-tree-item packet-tree-l2" data-field-id="client">Client ID: 0x0001</div>`;
                html += `<div class="packet-tree-item packet-tree-l2" data-field-id="session">Session ID: 0x0001</div>`;
                html += `<div class="packet-tree-item packet-tree-l2" data-field-id="proto_ver">Protocol Version: 0x01</div>`;
                html += `<div class="packet-tree-item packet-tree-l2" data-field-id="iface_ver">Interface Version: 0x01</div>`;
                html += `<div class="packet-tree-item packet-tree-l2" data-field-id="msg_type">Message Type: REQUEST (0x00)</div>`;
                html += `<div class="packet-tree-item packet-tree-l2" data-field-id="retcode">Return Code: E_OK (0x00)</div>`;
            } else if (pkt.protocol === 'DOIP') {
                html += `<div class="packet-tree-item packet-tree-l1 proto-doip" data-field-id="doip">`;
                html += `<span class="packet-tree-expand">▼</span>Diagnostic over IP (DoIP)`;
                html += `</div>`;
                html += `<div class="packet-tree-item packet-tree-l2" data-field-id="version">Protocol Version: 0x02</div>`;
                html += `<div class="packet-tree-item packet-tree-l2" data-field-id="inv_version">Inverse Protocol Version: 0xFD</div>`;
                html += `<div class="packet-tree-item packet-tree-l2" data-field-id="payload_type">Payload Type: 0x0001</div>`;
                html += `<div class="packet-tree-item packet-tree-l2" data-field-id="payload_len">Payload Length: ${bytesLen - 42}</div>`;
            }
            
            // === Data ===
            const dataLen = Math.max(0, bytesLen - 54);
            if (dataLen > 0) {
                html += `<div class="packet-tree-item packet-tree-l1" data-field-id="data">`;
                html += `<span class="packet-tree-expand">▼</span>Data (${dataLen} bytes)</div>`;
                html += `<div class="packet-tree-item packet-tree-l2" data-field-id="data.hex" style="font-family: monospace; font-size: 11px; word-break: break-all;">`;
                html += formatHexData(rawBytes, 54);
                html += `</div>`;
            }
            
            panel.innerHTML = html;
            
            // 添加点击事件监听器
            panel.querySelectorAll('.packet-tree-item').forEach(item => {
                item.addEventListener('click', function(e) {
                    e.stopPropagation();
                    const fieldId = this.dataset.fieldId;
                    const offset = this.dataset.offset;
                    const length = this.dataset.length;
                    
                    if (fieldId) {
                        panel.querySelectorAll('.packet-tree-item').forEach(el => el.classList.remove('selected'));
                        this.classList.add('selected');
                        selectedFieldId = fieldId;
                        
                        // 如果有 data-offset 属性，使用偏移量高亮
                        if (offset !== undefined) {
                            highlightHexByOffset(parseInt(offset), parseInt(length || 1));
                        } else {
                            highlightHexByField(fieldId);
                        }
                    }
                });
            });
            
            renderPacketHex(rawBytes);
        }
        
        // 辅助函数：格式化 MAC 地址
        function renderPacketHex(rawBytes) {
            
            if (!rawBytes || rawBytes.length === 0) {
                panel.innerHTML = '<div class="packet-detail-empty">No data available</div>';
                return;
            }
            
            
            // 每行 16 字节
            for (let i = 0; i < rawBytes.length; i += 32) {
                const lineBytes = rawBytes.substring(i, i + 32);
                
                html += '<div class="hex-line">';
                
                // Offset
                html += `<span class="hex-offset">${offset.toString(16).padStart(4, '0').toUpperCase()}</span>`;
                
                // Hex bytes - 添加数据属性用于双向映射
                html += '<span class="hex-bytes">';
                for (let j = 0; j < lineBytes.length; j += 2) {
                    const byte = lineBytes.substring(j, j + 2);
                    const byteIndex = (i + j) / 2;
                    html += `<span class="hex-byte" data-byte-index="${byteIndex}" title="Offset: 0x${byteIndex.toString(16).toUpperCase()}">${byte.toUpperCase()}</span>`;
                    if ((j / 2 + 1) % 8 === 0 && j < lineBytes.length - 2) {
                        html += ' ';
                    }
                }
                html += '</span>';
                
                // ASCII
                html += '<span class="hex-ascii">';
                for (let j = 0; j < lineBytes.length; j += 2) {
                    const char = (byte >= 32 && byte <= 126) ? String.fromCharCode(byte) : '.';
                    html += `<span class="hex-ascii-char" data-byte-index="${byteIndex}">${char}</span>`;
                }
                html += '</span>';
                
                html += '</div>';
            }
            
            html += '</div>';
            panel.innerHTML = html;
            
            // 添加点击事件监听器 - Hex → 协议层级
            panel.querySelectorAll('.hex-byte, .hex-ascii-char').forEach(el => {
                el.addEventListener('click', function(e) {
                    e.stopPropagation();
                    
                    // 高亮当前字节
                    panel.querySelectorAll('.hex-byte').forEach(hb => hb.classList.remove('selected'));
                    panel.querySelectorAll(`[data-byte-index="${byteIndex}"]`).forEach(be => {
                        if (be.classList.contains('hex-byte')) {
                            be.classList.add('selected');
                        }
                    });
                    
                    // 映射到协议层级
                    highlightFieldByHexByte(byteIndex);
                });
            });
        }

        // 解析 TCP Options
