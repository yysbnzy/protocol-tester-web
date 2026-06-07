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
// ===== 全局状态（显示过滤） =====
// 使用 window 对象挂载，避免重复声明导致的 SyntaxError
if (typeof window.currentDisplayFilter === 'undefined') {
    window.currentDisplayFilter = '';
}
if (typeof window.currentDisplayFilterEngine === 'undefined') {
    window.currentDisplayFilterEngine = null;
}

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
    
    window.currentDisplayFilter = input.value.trim();
    
    if (!window.currentDisplayFilter) {
        window.currentDisplayFilterEngine = null;
        if (status) status.textContent = '';
        // 重新渲染所有报文
        renderAllCapturePackets();
        return;
    }
    
    // 前端使用简单过滤（更复杂的用后端过滤）
    // 对于复杂表达式，调用后端过滤
    if (window.currentDisplayFilter.includes('==') || window.currentDisplayFilter.includes('!=') || 
        window.currentDisplayFilter.includes('>') || window.currentDisplayFilter.includes('<') ||
        window.currentDisplayFilter.includes('in')) {
        // 后端过滤
        if (status) status.textContent = '使用后端过滤...';
        applyBackendFilter();
    } else {
        // 前端简单过滤（协议名）
        if (status) status.textContent = `前端过滤: ${window.currentDisplayFilter}`;
        renderAllCapturePackets();
    }
}

function clearDisplayFilter() {
    const input = document.getElementById('displayFilterInput');
    const status = document.getElementById('displayFilterStatus');
    if (input) input.value = '';
    if (status) status.textContent = '';
    window.currentDisplayFilter = '';
    window.currentDisplayFilterEngine = null;
    renderAllCapturePackets();
}

function applyBackendFilter() {
    // 调用后端过滤 API
    fetch('/api/capture/filter/apply', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ filter: window.currentDisplayFilter })
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
        tbody.innerHTML = `<tr class="empty-row"><td colspan="7" style="text-align: center; color: #999; padding: 40px;">点击"开始捕获"按钮开始抓包...</td></tr>`;
        return;
    }
    
    tbody.innerHTML = '';
    let foreignCount = 0;
    
    capturedPackets.forEach((pkt, index) => {
        const pktNum = index + 1;
        
        // 前端过滤检查
        if (window.currentDisplayFilter && !frontendFilterMatch(pkt, window.currentDisplayFilter)) {
            return;
        }
        
        if (pkt.is_foreign) foreignCount++;
        
        const rowClass = getProtocolColorClass(pkt.protocol) + (pkt.is_foreign ? ' foreign-packet' : '');
        
        const tr = document.createElement('tr');
        tr.className = rowClass;
        tr.onclick = () => showPacketDetail(pkt.id);
        tr.dataset.packetId = pkt.id;
        tr.innerHTML = `
            <td>${pktNum}</td>
            <td>${formatTime(pkt)}</td>
            <td>${pkt.src_ip || '-'}</td>
            <td>${pkt.dst_ip || '-'}</td>
            <td class="protocol-cell">${pkt.protocol || '-'}</td>
            <td>${pkt.length || 0}</td>
            <td class="info-col" title="${pkt.info || '-'}">${pkt.info || '-'}</td>
        `;
        tbody.appendChild(tr);
    });
    
    document.getElementById('totalPackets').textContent = capturedPackets.length;
    document.getElementById('totalPacketsToolbar').textContent = capturedPackets.length;
    document.getElementById('foreignPacketsToolbar').textContent = foreignCount;
}

function renderFilteredPackets(filteredPackets) {
    const tbody = document.getElementById('captureTableBody');
    if (!tbody) return;
    
    tbody.innerHTML = '';
    let foreignCount = 0;
    
    filteredPackets.forEach((pkt, index) => {
        if (pkt.is_foreign) foreignCount++;
        
        const rowClass = getProtocolColorClass(pkt.protocol) + (pkt.is_foreign ? ' foreign-packet' : '');
        
        const tr = document.createElement('tr');
        tr.className = rowClass;
        tr.onclick = () => showPacketDetail(pkt.id);
        tr.dataset.packetId = pkt.id;
        tr.innerHTML = `
            <td>${index + 1}</td>
            <td>${formatTime(pkt)}</td>
            <td>${pkt.src_ip || '-'}</td>
            <td>${pkt.dst_ip || '-'}</td>
            <td class="protocol-cell">${pkt.protocol || '-'}</td>
            <td>${pkt.length || 0}</td>
            <td class="info-col" title="${pkt.info || '-'}">${pkt.info || '-'}</td>
        `;
        tbody.appendChild(tr);
    });
    
    document.getElementById('totalPackets').textContent = filteredPackets.length;
    document.getElementById('totalPacketsToolbar').textContent = filteredPackets.length;
    document.getElementById('foreignPacketsToolbar').textContent = foreignCount;
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
            if (!window.captureRunning) {
                await startCapture();
            } else {
                await stopCapture();
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
                const response = await fetch('/api/capture/packets');
                const contentType = response.headers.get('content-type') || '';
                
                // 检查响应是否是JSON
                if (!contentType || !contentType.includes('application/json')) {
                    // 不是JSON，可能是错误页面，忽略
                    return;
                }
                
                const result = await response.json();
                
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
                        <td colspan="7" style="text-align: center; color: #999; padding: 40px;">
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
                
                html += `<tr class="${rowClass}" onclick="showPacketDetail('${pkt.id}')">`;
                html += `<td>${pktNum}</td>`;
                html += `<td>${formatTime(pkt)}</td>`;
                html += `<td>${pkt.src_ip || '-'}</td>`;
                html += `<td>${pkt.dst_ip || '-'}</td>`;
                html += `<td class="protocol-cell">${pkt.protocol || '-'}</td>`;
                html += `<td>${pkt.length || 0}</td>`;
                html += `<td class="info-col" title="${pkt.info || '-'}">${pkt.info || '-'}</td>`;
                html += '</tr>';
            });
            
            tbody.innerHTML = html;
            
            // 更新统计
            document.getElementById('totalPackets').textContent = packets.length;
            document.getElementById('totalPacketsToolbar').textContent = packets.length;
            document.getElementById('foreignPacketsToolbar').textContent = foreignCount;
        }
        
        // 追加新报文到表格（Wireshark风格 - 实时追加）
        function appendCaptureList(newPackets, totalCount) {
            const container = document.querySelector('.capture-table-container');
            const tbody = document.getElementById('captureTableBody');
            
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
            let foreignCount = parseInt(document.getElementById('foreignPacketsToolbar').textContent) || 0;
            
            newPackets.forEach((pkt, index) => {
                if (pkt.is_foreign) foreignCount++;
                
                const colorClass = getProtocolColorClass(pkt.protocol);
                const rowClass = colorClass + (pkt.is_foreign ? ' foreign-packet' : '');
                const pktNum = totalCount - newPackets.length + index + 1;
                
                const row = document.createElement('tr');
                row.className = rowClass;
                row.onclick = () => showPacketDetail(pkt.id);
                row.dataset.packetId = pkt.id;
                
                row.innerHTML = `
                    <td>${pktNum}</td>
                    <td>${formatTime(pkt)}</td>
                    <td>${pkt.src_ip || '-'}</td>
                    <td>${pkt.dst_ip || '-'}</td>
                    <td class="protocol-cell">${pkt.protocol || '-'}</td>
                    <td>${pkt.length || 0}</td>
                    <td class="info-col" title="${pkt.info || '-'}">${pkt.info || '-'}</td>
                `;
                
                // 追加到表格末尾（Wireshark风格：新报文在底部）
                tbody.appendChild(row);
            });
            
            // 更新统计
            document.getElementById('foreignPacketsToolbar').textContent = foreignCount;
            
            // 如果之前在底部，自动滚动到新报文
            if (isScrolledToBottom) {
                container.scrollTop = container.scrollHeight;
            }
        }
        
        // 清空捕获列表
        async function clearCapture() {
            try {
                const response = await fetch('/api/capture/clear', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' }
                });
                const result = await response.json();
                
                
                if (result.success) {
                    capturedPackets = [];
                    document.getElementById('captureTableBody').innerHTML = `
                        <tr class="empty-row">
                            <td colspan="7" style="text-align: center; color: #999; padding: 40px;">
                                点击"开始捕获"按钮开始抓包...
                            </td>
                        </tr>
                    `;
                    document.getElementById('totalPackets').textContent = '0';
                    document.getElementById('totalPacketsToolbar').textContent = '0';
                    document.getElementById('foreignPacketsToolbar').textContent = '0';
                    
                    // 重置报文详情
                    document.getElementById('packetDetailTitle').textContent = '报文详情 - 未选择';
                    document.getElementById('packetTreePanel').innerHTML = '<div class="packet-detail-empty">点击上方表格中的报文查看详情</div>';
                    document.getElementById('packetHexPanel').innerHTML = '<div class="packet-detail-empty">点击上方表格中的报文查看详情</div>';
                    currentSelectedPacket = null;
                    
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
            const nic = document.getElementById('nicSelect').value;
            const protocols = [];
            if (document.getElementById('filterTCP')?.checked) protocols.push('TCP');
            if (document.getElementById('filterUDP')?.checked) protocols.push('UDP');
            if (document.getElementById('filterICMP')?.checked) protocols.push('ICMP');
            if (document.getElementById('filterARP')?.checked) protocols.push('ARP');
            
            addLog(`[捕获] 正在启动... 网卡: ${nic}`);
            
            const bpfFilter = document.getElementById('bpfFilterInput')?.value?.trim() || null;
            
            try {
                const response = await fetch('/api/capture/start', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        interface: nic,
                        protocols: protocols,
                        bpf_filter: bpfFilter
                    })
                });
                const result = await response.json();
                
                
                if (result.success) {
                    window.captureRunning = true;
                    document.getElementById('startCaptureBtn').style.display = 'none';
                    document.getElementById('stopCaptureBtn').style.display = 'block';
                    document.getElementById('captureStatus').textContent = '🔴 捕获中';
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
                const response = await fetch('/api/capture/stop', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ force: true })
                });
                const result = await response.json();
                
                
                if (result.success) {
                    window.captureRunning = false;
                    document.getElementById('startCaptureBtn').style.display = 'block';
                    document.getElementById('stopCaptureBtn').style.display = 'none';
                    document.getElementById('captureStatus').textContent = '⏹️ 停止';
                    addLog(`[捕获] ✓ 已停止 - 共捕获 ${result.total_packets || 0} 个报文`);
                    stopCapturePolling();
                    // 刷新统计面板
                    refreshStatistics();
                    // 更新总报文数（从捕获数据计算）
                    document.getElementById('totalPackets').textContent = capturedPackets.length;
                    document.getElementById('totalPacketsToolbar').textContent = capturedPackets.length;
                } else {
                    addLog(`[捕获] ✗ 停止失败 - ${result.message}`);
                }
            } catch (error) {
                window.captureRunning = false;
                document.getElementById('startCaptureBtn').style.display = 'block';
                document.getElementById('stopCaptureBtn').style.display = 'none';
                document.getElementById('captureStatus').textContent = '⏹️ 停止';
                stopCapturePolling();
                addLog('[捕获] ✓ 已停止');
                // 刷新统计面板
                refreshStatistics();
                document.getElementById('totalPackets').textContent = capturedPackets.length;
                document.getElementById('totalPacketsToolbar').textContent = capturedPackets.length;
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

            // 展开详情面板
            const detailContainer = document.getElementById('packetDetailContainer');
            if (detailContainer) {
                detailContainer.classList.remove('collapsed');
                detailContainer.classList.add('expanded');
            }
            
            // 隐藏提示（已选择报文）
            const hintEl = document.getElementById('packetDetailHint');
            if (hintEl) hintEl.style.display = 'none';
            
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
            if (!panel) return;

            // Fallback: get rawBytes from pkt if not provided
            if (!rawBytes) {
                rawBytes = pkt.raw_bytes || pkt.hex || '';
            }

            let html = '';
            
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
                html += `<div class="packet-tree-item packet-tree-l1" data-field-id="data" data-offset="54" data-length="${dataLen}">`;
                html += `<span class="packet-tree-expand">▼</span>Data (${dataLen} bytes)</div>`;
                html += `<div class="packet-tree-item packet-tree-l2" data-field-id="data.hex" data-offset="54" data-length="${dataLen}" style="font-family: monospace; font-size: 11px; word-break: break-all;">`;
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
        }
        
        // 辅助函数：格式化 MAC 地址
        function renderPacketHex(rawBytes) {
            const panel = document.getElementById('packetHexPanel');
            
            if (!rawBytes || rawBytes.length === 0) {
                panel.innerHTML = '<div class="packet-detail-empty">No data available</div>';
                return;
            }
            
            let html = '<div class="hex-view-container">';
            
            // 每行 16 字节 (32 hex chars)
            for (let i = 0; i < rawBytes.length; i += 32) {
                const lineBytes = rawBytes.substring(i, i + 32);
                const offset = i / 2;
                
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
                    const byteHex = lineBytes.substring(j, j + 2);
                    const byteVal = parseInt(byteHex, 16);
                    const byteIndex = (i + j) / 2;
                    const char = (byteVal >= 32 && byteVal <= 126) ? String.fromCharCode(byteVal) : '.';
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
                    const byteIndex = parseInt(this.dataset.byteIndex);
                    
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

// 格式化 Hex 数据（用于协议层级树中的 data.hex 显示）
function formatHexData(rawBytes, startOffset) {
    if (!rawBytes || rawBytes.length === 0) return '';
    let result = '';
    for (let i = startOffset * 2; i < rawBytes.length; i += 2) {
        result += rawBytes.substring(i, i + 2) + ' ';
        if ((i / 2 + 1) % 16 === 0) result += '\n';
    }
    return result.trim();
}

// 高亮 Hex 字节（通过偏移量和长度）
function highlightHexByOffset(offset, length) {
    const hexPanel = document.getElementById('packetHexPanel');
    if (!hexPanel) return;
    
    hexPanel.querySelectorAll('.hex-byte').forEach(el => {
        el.classList.remove('selected');
    });
    
    for (let i = offset; i < offset + length; i++) {
        hexPanel.querySelectorAll(`[data-byte-index="${i}"]`).forEach(el => {
            if (el.classList.contains('hex-byte')) {
                el.classList.add('selected');
            }
        });
    }
}

// 高亮 Hex 字节（通过字段ID）
function highlightHexByField(fieldId) {
    // 字段到偏移量的映射表
    const fieldOffsets = {
        'frame': [0, 14],
        'eth': [0, 14],
        'dst_mac': [0, 6],
        'src_mac': [6, 6],
        'ethertype': [12, 2],
        'ip': [14, 20],
        'version_ihl': [14, 1],
        'tos': [15, 1],
        'total_len': [16, 2],
        'id': [18, 2],
        'flags_frag': [20, 2],
        'ttl': [22, 1],
        'protocol': [23, 1],
        'checksum': [24, 2],
        'src_ip': [26, 4],
        'dst_ip': [30, 4],
        'tcp': [34, 20],
        'src_port': [34, 2],
        'dst_port': [36, 2],
        'seq': [38, 4],
        'ack': [42, 4],
        'data_offset': [46, 1],
        'flags': [47, 1],
        'window': [48, 2],
        'tcp_checksum': [50, 2],
        'urgent': [52, 2],
        'udp': [34, 8],
        'udp_src_port': [34, 2],
        'udp_dst_port': [36, 2],
        'udp_length': [38, 2],
        'udp_checksum': [40, 2],
        'icmp': [34, 8],
        'icmp_type': [34, 1],
        'icmp_code': [35, 1],
        'icmp_checksum': [36, 2],
        'icmp_id': [38, 2],
        'icmp_seq': [40, 2],
        'arp': [14, 28],
        'hw_type': [14, 2],
        'proto_type': [16, 2],
        'hw_size': [18, 1],
        'proto_size': [19, 1],
        'opcode': [20, 2],
        'arp_src_mac': [22, 6],
        'arp_src_ip': [28, 4],
        'arp_dst_mac': [32, 6],
        'arp_dst_ip': [38, 4],
        'data': [54, -1],  // data offset starts at 54, length is dynamic
        'data.hex': [54, -1],
    };
    
    const offset = fieldOffsets[fieldId];
    if (offset) {
        let length = offset[1];
        // For data layer, calculate length from current packet's raw bytes
        if (length === -1 && currentSelectedPacket && currentSelectedPacket.raw_bytes) {
            const rawBytes = currentSelectedPacket.raw_bytes;
            const bytesLen = rawBytes.length / 2;
            length = Math.max(0, bytesLen - offset[0]);
        }
        highlightHexByOffset(offset[0], length);
    }
}

// 高亮协议层级字段（通过 Hex 字节索引）
function highlightFieldByHexByte(byteIndex) {
    const treePanel = document.getElementById('packetTreePanel');
    if (!treePanel) return;
    
    // 简单的偏移量到字段映射
    let fieldId = null;
    if (byteIndex < 14) {
        fieldId = 'eth';
    } else if (byteIndex < 34) {
        fieldId = 'ip';
    } else if (byteIndex < 54) {
        fieldId = 'tcp';
    } else {
        fieldId = 'data';  // data layer
    }
    
    if (!fieldId) return;
    
    treePanel.querySelectorAll('.packet-tree-item').forEach(el => {
        el.classList.remove('selected');
        if (el.dataset.fieldId === fieldId) {
            el.classList.add('selected');
        }
    });
}

// ===== 迭代2: CSV/JSON 导出 =====

async function exportJSON() {
    try {
        addLog('[导出] 正在导出 JSON...');
        const response = await fetch('/api/capture/export/json', { method: 'GET' });
        if (response.ok) {
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `capture_${new Date().toISOString().slice(0,19).replace(/:/g,'-')}.json`;
            document.body.appendChild(a);
            a.click();
            a.remove();
            window.URL.revokeObjectURL(url);
            addLog('[导出] JSON 导出成功');
        } else {
            addLog('[导出] JSON 导出失败');
        }
    } catch (error) {
        addLog(`[导出] JSON 错误: ${error.message}`);
    }
}

// ===== 迭代2: 统计面板 =====

function refreshStatistics() {
    // 协议分布统计
    const protoCounts = {};
    let totalPackets = 0;
    let foreignPackets = 0;

    capturedPackets.forEach(pkt => {
        totalPackets++;
        if (pkt.is_foreign) foreignPackets++;
        const proto = pkt.protocol || 'Unknown';
        protoCounts[proto] = (protoCounts[proto] || 0) + 1;
    });

    // 更新统计数字（侧边栏）
    document.getElementById('statTotalPackets').textContent = totalPackets;
    document.getElementById('statForeignPackets').textContent = foreignPackets;

    // 同步更新工具栏数字（确保一致）
    const totalPacketsEl = document.getElementById('totalPackets');
    const totalPacketsToolbarEl = document.getElementById('totalPacketsToolbar');
    const foreignPacketsToolbarEl = document.getElementById('foreignPacketsToolbar');

    if (totalPacketsEl) totalPacketsEl.textContent = totalPackets;
    if (totalPacketsToolbarEl) totalPacketsToolbarEl.textContent = totalPackets;
    if (foreignPacketsToolbarEl) foreignPacketsToolbarEl.textContent = foreignPackets;

    // 更新协议分布图表
    updateProtocolChart(protoCounts, totalPackets);

    // 更新流统计（异步）
    fetchStreamStatistics();
}

function updateProtocolChart(protoCounts, total) {
    const chartBars = document.getElementById('chartBars');
    if (!chartBars) return;
    
    if (total === 0) {
        chartBars.innerHTML = '<div style="text-align: center; color: #999; padding: 20px;">暂无数据</div>';
        return;
    }
    
    const colors = {
        'TCP': '#4caf50',
        'UDP': '#2196f3',
        'ICMP': '#ff9800',
        'ARP': '#9c27b0',
        'DOIP': '#f44336',
        'SOMEIP': '#00bcd4',
        'SOMEIP-SD': '#009688',
        'HTTP': '#795548',
        'HTTPS': '#607d8b',
        'DNS': '#e91e63',
        'SSH': '#3f51b5',
    };
    
    const sortedProtos = Object.entries(protoCounts).sort((a, b) => b[1] - a[1]);
    
    let html = '';
    sortedProtos.forEach(([proto, count]) => {
        const pct = total > 0 ? (count / total * 100).toFixed(1) : 0;
        const color = colors[proto] || '#999';
        html += `
            <div class="chart-bar-row">
                <span class="chart-bar-label">${proto}</span>
                <div class="chart-bar-track">
                    <div class="chart-bar-fill" style="width: ${pct}%; background: ${color};"></div>
                </div>
                <span class="chart-bar-value">${count} (${pct}%)</span>
            </div>
        `;
    });
    
    chartBars.innerHTML = html;
}

async function fetchStreamStatistics() {
    try {
        const response = await fetch('/api/capture/streams/statistics');
        const result = await response.json();
        if (result.success) {
            const stats = result.statistics;
            document.getElementById('statTotalStreams').textContent = stats.total_streams || 0;
        }
    } catch (e) {
        // 静默失败
    }
}

// 捕获新报文时自动刷新统计
toggleCapture = (function(original) {
    return async function() {
        const result = await original.apply(this, arguments);
        // 每次轮询后刷新统计
        return result;
    };
})(toggleCapture);

// 在 fetchCapturedPackets 成功后调用 refreshStatistics
// 需要在原有 fetchCapturedPackets 中插入

// ===== 迭代2: 流管理器 =====

async function showStreamManager() {
    document.getElementById('streamModal').style.display = 'flex';
    await refreshStreamList();
}

function closeStreamModal() {
    document.getElementById('streamModal').style.display = 'none';
}

async function refreshStreamList() {
    const tbody = document.getElementById('streamTableBody');
    if (!tbody) return;
    
    try {
        const response = await fetch('/api/capture/streams');
        const result = await response.json();
        
        if (!result.success || !result.streams || result.streams.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: #999; padding: 40px;">暂无流数据</td></tr>';
            return;
        }
        
        tbody.innerHTML = '';
        result.streams.forEach((stream, index) => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td>${index + 1}</td>
                <td><span class="protocol-badge protocol-${(stream.protocol || '').toLowerCase()}">${stream.protocol}</span></td>
                <td>${stream.src_ip}:${stream.src_port}</td>
                <td>${stream.dst_ip}:${stream.dst_port}</td>
                <td>${stream.packet_count}</td>
                <td>${stream.total_bytes}</td>
                <td>
                    <button class="mini-btn" onclick="followStream('${stream.id}')">Follow Stream</button>
                </td>
            `;
            tbody.appendChild(tr);
        });
    } catch (error) {
        tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: #f44336; padding: 40px;">加载失败: ${error.message}</td></tr>`;
    }
}

// ===== 迭代2: Follow Stream =====

let currentFollowStreamId = null;

async function followStream(streamId) {
    currentFollowStreamId = streamId;
    document.getElementById('followStreamModal').style.display = 'flex';
    await refreshFollowStream();
}

function closeFollowStreamModal() {
    document.getElementById('followStreamModal').style.display = 'none';
    currentFollowStreamId = null;
}

async function refreshFollowStream() {
    if (!currentFollowStreamId) return;
    
    const format = document.getElementById('followFormat').value;
    const titleEl = document.getElementById('followStreamTitle');
    const infoEl = document.getElementById('followStreamInfo');
    const contentEl = document.getElementById('followStreamContent');
    
    try {
        const response = await fetch(`/api/capture/streams/${currentFollowStreamId}/follow?format=${format}`);
        const result = await response.json();
        
        if (!result.success) {
            contentEl.innerHTML = `<div style="color: #f44336; padding: 20px;">${result.message || '加载失败'}</div>`;
            return;
        }
        
        const stream = result.stream;
        titleEl.textContent = `Follow ${stream.protocol} Stream - ${stream.client_addr} ↔ ${stream.server_addr}`;
        
        infoEl.innerHTML = `
            <span>报文数: ${stream.packet_count}</span>
            <span>Client → Server: ${stream.total_client_bytes} bytes</span>
            <span>Server → Client: ${stream.total_server_bytes} bytes</span>
        `;
        
        if (format === 'ascii') {
            let html = '<div class="follow-lines">';
            stream.lines.forEach(line => {
                const dirLabel = line.direction === 'client' ? 'C→S' : 'S→C';
                const dirClass = line.direction === 'client' ? 'client-line' : 'server-line';
                html += `<div class="follow-line ${dirClass}"><span class="follow-dir">${dirLabel}</span><span class="follow-data">${escapeHtml(line.data)}</span></div>`;
            });
            html += '</div>';
            contentEl.innerHTML = html;
        } else if (format === 'hex') {
            let html = '<div class="follow-lines">';
            stream.lines.forEach(line => {
                const dirLabel = line.direction === 'client' ? 'C→S' : 'S→C';
                const dirClass = line.direction === 'client' ? 'client-line' : 'server-line';
                html += `<div class="follow-line ${dirClass}"><span class="follow-dir">${dirLabel}</span><pre class="follow-hex">${escapeHtml(line.data)}</pre></div>`;
            });
            html += '</div>';
            contentEl.innerHTML = html;
        } else {
            contentEl.innerHTML = `<pre style="font-size: 11px; overflow: auto; max-height: 500px;">${escapeHtml(stream.lines.map(l => l.data).join('\n'))}</pre>`;
        }
    } catch (error) {
        contentEl.innerHTML = `<div style="color: #f44336; padding: 20px;">加载失败: ${error.message}</div>`;
    }
}

// 初始化：报文详情面板折叠/展开
function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// ===== Filter Tooltip (Hover) =====

const BPF_TOOLTIP_DATA = {
    '协议过滤': ['tcp', 'udp', 'icmp', 'arp'],
    '端口过滤': ['port 80', 'port 443', 'port 53', 'port 22', 'port 8080'],
    'IP过滤': ['host 192.168.1.1', 'src host 192.168.1.1', 'dst host 192.168.1.1'],
    '组合': ['tcp and port 80', 'udp and port 53', 'not arp', 'tcp or udp'],
};

const DISPLAY_TOOLTIP_DATA = {
    '协议过滤': ['tcp', 'udp', 'icmp', 'arp', 'http', 'dns'],
    'IP过滤': ['ip.src == 192.168.1.1', 'ip.dst == 192.168.1.1', 'ip.addr == 192.168.1.1'],
    '端口过滤': ['tcp.port == 80', 'udp.port == 53', 'tcp.port == 443'],
    '组合': ['tcp and ip.src == 192.168.1.1', 'udp and dns', 'http or https'],
};

function initFilterTooltips() {
    document.querySelectorAll('.filter-tooltip-icon').forEach(icon => {
        const type = icon.dataset.filterType;
        const data = type === 'bpf' ? BPF_TOOLTIP_DATA : DISPLAY_TOOLTIP_DATA;
        
        // Build tooltip HTML
        let html = '<div class="filter-tooltip">';
        html += '<div class="tooltip-title">' + (type === 'bpf' ? '前置过滤公式' : '显示过滤公式') + '</div>';
        
        for (const [group, items] of Object.entries(data)) {
            html += '<div class="tooltip-group">';
            html += '<div class="tooltip-group-title">' + group + '</div>';
            html += '<div class="tooltip-list">';
            items.forEach(item => {
                html += '<span class="tooltip-item">' + item + '</span>';
            });
            html += '</div></div>';
        }
        html += '</div>';
        
        icon.innerHTML = '❗' + html;
    });
}

// Init tooltips on DOM ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initFilterTooltips);
} else {
    initFilterTooltips();
}

