        // 加载网卡列表
        async function loadNics() {
            const select = document.getElementById('nicSelect');
            const infoSpan = document.getElementById('nicInfo');
            
            // DOM 未就绪则延迟重试
            if (!select) {
                console.warn('[loadNics] nicSelect not found, retrying in 500ms');
                setTimeout(loadNics, 500);
                return;
            }
            
            try {
                console.log('[loadNics] Fetching /api/nics...');
                const response = await fetch('/api/nics');
                console.log('[loadNics] Response status:', response.status);
                
                const result = await response.json();
                console.log('[loadNics] Result:', result);
                
                if (result.success && result.nics && result.nics.length > 0) {
                    // 保存当前选中值
                    const currentValue = select.value;
                    
                    // 清空并添加选项
                    select.innerHTML = '';
                    
                    result.nics.forEach(nic => {
                        const option = document.createElement('option');
                        option.value = nic.name;
                        option.textContent = `${nic.name} (${nic.ip || 'N/A'})`;
                        select.appendChild(option);
                    });
                    
                    // 恢复选中值或默认选第一个
                    if (currentValue && Array.from(select.options).some(o => o.value === currentValue)) {
                        select.value = currentValue;
                    } else if (select.options.length > 0) {
                        select.selectedIndex = 0;
                    }
                    
                    // 更新网卡信息显示
                    updateNicInfo();
                    
                    console.log(`[loadNics] Loaded ${result.nics.length} NICs`);
                    addLog(`[NIC] 已加载 ${result.nics.length} 个网卡`);
                } else {
                    console.warn('[loadNics] No NICs in response:', result);
                    select.innerHTML = '<option value="">无可用网卡</option>';
                    if (infoSpan) infoSpan.textContent = '无网卡信息';
                    addLog('[NIC] 加载网卡失败: ' + (result.message || '后端未返回网卡数据'));
                }
            } catch (error) {
                console.error('[loadNics] Error:', error);
                select.innerHTML = '<option value="">网卡加载失败</option>';
                if (infoSpan) infoSpan.textContent = '网卡加载失败';
                addLog('[NIC] 加载网卡错误: ' + error.message);
            }
        }
        
        // 更新网卡信息显示
        function updateNicInfo() {
            const select = document.getElementById('nicSelect');
            const infoSpan = document.getElementById('nicInfo');
            if (!select || !infoSpan) return;
            
            const selectedOption = select.options[select.selectedIndex];
            if (selectedOption) {
                const text = selectedOption.textContent;
                // 提取IP地址
                const match = text.match(/\(([^)]+)\)/);
                const ip = match ? match[1] : 'N/A';
                infoSpan.textContent = `IP: ${ip}`;
            } else {
                infoSpan.textContent = '未选择网卡';
            }
        }

        // 存储所有网卡数据（供其他函数使用）
        let allNics = [];
        
        // 获取指定网卡的IP
        function getNicIp(nicName) {
            const nic = allNics.find(n => n.name === nicName);
            return nic ? nic.ip : null;
        }
        
        // 获取指定网卡的MAC
        function getNicMac(nicName) {
            const nic = allNics.find(n => n.name === nicName);
            return nic ? nic.mac : null;
        }

        function exportLog() {
            const log = document.getElementById('logOutput');
            if (!log || !log.value) {
                alert('No logs to export');
                return;
            }
            const blob = new Blob([log.value], { type: 'text/plain' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'protocol-tester-log-' + new Date().toISOString().slice(0,10) + '.txt';
            a.click();
            URL.revokeObjectURL(url);
        }

        function exportCapture() {
            fetch('/api/capture/export/pcap')
                .then(r => r.blob())
                .then(blob => {
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = 'capture-' + new Date().toISOString().slice(0,10) + '.pcap';
                    a.click();
                    URL.revokeObjectURL(url);
                })
                .catch(e => alert('Export failed: ' + e));
        }
        // 协议定义 (Wireshark 风格) - Bug Fix 8: 添加协议前缀避免字段名冲突
        const protocolFields = {
            'ARP': ['ARP.proto.type', 'ARP.opcode', 'ARP.src.hw_mac', 'ARP.dst.hw_mac', 'ARP.dst_ip'],
            'IP': ['IP.version', 'IP.tos', 'IP.id', 'IP.ttl', 'IP.checksum', 'IP.src', 'IP.dst'],
            'TCP': ['TCP.srcport', 'TCP.dstport', 'TCP.seq', 'TCP.ack', 'TCP.flags', 'TCP.window_size', 'TCP.checksum', 'TCP.options'],
            'UDP': ['UDP.srcport', 'UDP.dstport', 'UDP.checksum'],
            'ICMP': ['ICMP.type', 'ICMP.code', 'ICMP.checksum', 'ICMP.id', 'ICMP.seq'],
            'SOMEIP': ['SOMEIP.service', 'SOMEIP.method', 'SOMEIP.client', 'SOMEIP.session',
                      'SOMEIP.proto_ver', 'SOMEIP.iface_ver', 'SOMEIP.msg_type', 'SOMEIP.retcode', 'SOMEIP.payload'],
            'SOMEIP-SD': ['SOMEIP-SD.service', 'SOMEIP-SD.method', 'SOMEIP-SD.client', 'SOMEIP-SD.session', 'SOMEIP-SD.proto_ver', 'SOMEIP-SD.iface_ver', 'SOMEIP-SD.msg_type', 'SOMEIP-SD.retcode', 'SOMEIP-SD.payload', 'SOMEIP-SD.flags', 'SOMEIP-SD.entry_type', 'SOMEIP-SD.sd_service', 'SOMEIP-SD.instance_id', 'SOMEIP-SD.ttl', 'SOMEIP-SD.option_type'],
            'DOIP': ['DOIP.version', 'DOIP.inv_version', 'DOIP.payload_type', 'DOIP.payload']
        };

        const legalDefaults = {
            'IP': {'IP.version': '4', 'IP.tos': '0x00', 'IP.id': '0x1234', 'IP.ttl': '64', 'IP.checksum': '0x0000',
                   'IP.src': '192.168.1.100', 'IP.dst': '192.168.1.1'},
            'TCP': {'TCP.srcport': '8080', 'TCP.dstport': '80', 'TCP.seq': '0',
                   'TCP.ack': '0', 'TCP.flags': '0x02 (SYN)', 'TCP.window_size': '65535', 'TCP.checksum': '0x0000',
                   'TCP.options': '0x020405b4'},  // MSS = 1460
            'UDP': {'UDP.srcport': '12345', 'UDP.dstport': '53', 'UDP.checksum': '0x0000'},
            'ARP': {'ARP.proto.type': '0x0800 (IPv4)', 'ARP.opcode': '0x0001 (Request)',
                   'ARP.src.hw_mac': '00:11:22:33:44:55', 'ARP.dst.hw_mac': '00:00:00:00:00:00', 'ARP.dst_ip': '192.168.1.1'},
            'ICMP': {'ICMP.type': '8 (Echo Request)', 'ICMP.code': '0', 'ICMP.checksum': '0x0000', 'ICMP.id': '0x1234', 'ICMP.seq': '1'},
            'SOMEIP': {'SOMEIP.service': '0x1234', 'SOMEIP.method': '0x5678', 'SOMEIP.client': '0x0001', 'SOMEIP.session': '0x0001',
                      'SOMEIP.proto_ver': '0x01', 'SOMEIP.iface_ver': '0x01', 'SOMEIP.msg_type': '0x00 (REQUEST)',
                      'SOMEIP.retcode': '0x00 (E_OK)', 'SOMEIP.payload': '0xDEADBEEF'},
            'SOMEIP-SD': {'SOMEIP-SD.service': '0xFFFF', 'SOMEIP-SD.method': '0x8100', 'SOMEIP-SD.client': '0x0000', 'SOMEIP-SD.session': '0x0001',
                      'SOMEIP-SD.proto_ver': '0x01', 'SOMEIP-SD.iface_ver': '0x01', 'SOMEIP-SD.msg_type': '0x02 (NOTIFICATION)',
                      'SOMEIP-SD.retcode': '0x00 (E_OK)', 'SOMEIP-SD.payload': '-payload-sd-', 'SOMEIP-SD.flags': '0xC0', 'SOMEIP-SD.entry_type': '0x01 (Offer)',
                      'SOMEIP-SD.sd_service': '0x1234', 'SOMEIP-SD.instance_id': '0x0001', 'SOMEIP-SD.ttl': '3', 'SOMEIP-SD.option_type': '0x04 (IPv4 Endpoint)'},
            'DOIP': {'DOIP.version': '0x02', 'DOIP.inv_version': '0xFD', 'DOIP.payload_type': '0x0001', 'DOIP.payload': '0x00'}
        };


        // Field bit offsets for hex highlighting - 完整协议定义
        const fieldBitOffsets = {
            // Ethernet Layer
            'ETHERNET': {
                'dst_mac': { offset: 0, length: 6, name: 'Destination MAC' },
                'src_mac': { offset: 6, length: 6, name: 'Source MAC' },
                'ethertype': { offset: 12, length: 2, name: 'Type' }
            },
            // ARP
            'ARP': {
                'hw_type': { offset: 14, length: 2, name: 'Hardware Type' },
                'proto_type': { offset: 16, length: 2, name: 'Protocol Type' },
                'hw_size': { offset: 18, length: 1, name: 'Hardware Size' },
                'proto_size': { offset: 19, length: 1, name: 'Protocol Size' },
                'opcode': { offset: 20, length: 2, name: 'Opcode' },
                'src_mac': { offset: 22, length: 6, name: 'Sender MAC' },
                'src_ip': { offset: 28, length: 4, name: 'Sender IP' },
                'dst_mac': { offset: 32, length: 6, name: 'Target MAC' },
                'dst_ip': { offset: 38, length: 4, name: 'Target IP' }
            },
            // IP
            'IP': {
                'version_ihl': { offset: 14, length: 1, name: 'Version/IHL' },
                'tos': { offset: 15, length: 1, name: 'TOS' },
                'total_len': { offset: 16, length: 2, name: 'Total Length' },
                'id': { offset: 18, length: 2, name: 'Identification' },
                'flags_frag': { offset: 20, length: 2, name: 'Flags/Fragment' },
                'ttl': { offset: 22, length: 1, name: 'TTL' },
                'protocol': { offset: 23, length: 1, name: 'Protocol' },
                'checksum': { offset: 24, length: 2, name: 'Checksum' },
                'src_ip': { offset: 26, length: 4, name: 'Source IP' },
                'dst_ip': { offset: 30, length: 4, name: 'Destination IP' }
            },
            // TCP
            'TCP': {
                'src_port': { offset: 34, length: 2, name: 'Source Port' },
                'dst_port': { offset: 36, length: 2, name: 'Destination Port' },
                'seq': { offset: 38, length: 4, name: 'Sequence Number' },
                'ack': { offset: 42, length: 4, name: 'Ack Number' },
                'data_offset': { offset: 46, length: 1, name: 'Data Offset' },
                'flags': { offset: 47, length: 1, name: 'Flags' },
                'window': { offset: 48, length: 2, name: 'Window Size' },
                'checksum': { offset: 50, length: 2, name: 'Checksum' },
                'urgent': { offset: 52, length: 2, name: 'Urgent Pointer' },
                'options': { offset: 54, length: 40, name: 'Options' }  // 最大 40 字节的 Options
            },
            // UDP
            'UDP': {
                'src_port': { offset: 34, length: 2, name: 'Source Port' },
                'dst_port': { offset: 36, length: 2, name: 'Destination Port' },
                'length': { offset: 38, length: 2, name: 'Length' },
                'checksum': { offset: 40, length: 2, name: 'Checksum' }
            },
            // ICMP
            'ICMP': {
                'type': { offset: 34, length: 1, name: 'Type' },
                'code': { offset: 35, length: 1, name: 'Code' },
                'checksum': { offset: 36, length: 2, name: 'Checksum' },
                'id': { offset: 38, length: 2, name: 'ID' },
                'seq': { offset: 40, length: 2, name: 'Sequence' }
            },
            // SOME/IP
            'SOMEIP': {
                'service_id': { offset: 0, bitStart: 0, bitLen: 16, name: 'Service ID' },
                'method_id': { offset: 2, bitStart: 0, bitLen: 16, name: 'Method ID' },
                'length': { offset: 4, bitStart: 0, bitLen: 32, name: 'Length' },
                'client_id': { offset: 8, bitStart: 0, bitLen: 16, name: 'Client ID' },
                'session_id': { offset: 10, bitStart: 0, bitLen: 16, name: 'Session ID' },
                'proto_ver': { offset: 12, bitStart: 0, bitLen: 8, name: 'Protocol Version' },
                'iface_ver': { offset: 13, bitStart: 0, bitLen: 8, name: 'Interface Version' },
                'msg_type': { offset: 14, bitStart: 0, bitLen: 8, name: 'Message Type' },
                'retcode': { offset: 15, bitStart: 0, bitLen: 8, name: 'Return Code' }
            },
            'SOMEIP-SD': {
                'flags': { offset: 16, bitStart: 0, bitLen: 8, name: 'Flags (Reboot/Unicast/CID)' },
                'entry_type': { offset: 20, bitStart: 0, bitLen: 8, name: 'Entry Type' },
                'service': { offset: 24, bitStart: 0, bitLen: 16, name: 'Service ID' },
                'instance_id': { offset: 26, bitStart: 0, bitLen: 16, name: 'Instance ID' },
                'ttl': { offset: 29, bitStart: 0, bitLen: 24, name: 'TTL (seconds)' },
                'option_type': { offset: 36, bitStart: 0, bitLen: 8, name: 'Option Type' }
            },
            // DoIP
            'DOIP': {
                'version': { offset: 0, bitStart: 0, bitLen: 8, name: 'Protocol Version' },
                'inv_version': { offset: 1, bitStart: 0, bitLen: 8, name: 'Inverse Version' },
                'payload_type': { offset: 2, bitStart: 0, bitLen: 16, name: 'Payload Type' },
                'payload_len': { offset: 4, bitStart: 0, bitLen: 32, name: 'Payload Length' }
            }
        };

        const illegalDefaults = {
            'IP': {'IP.version': '0xFF', 'IP.tos': '0xFF', 'IP.id': '0xFFFF',
                   'IP.ttl': '0', 'IP.checksum': '0xFFFF', 'IP.src': '999.999.999.999', 'IP.dst': '256.256.256.256'},
            'TCP': {'TCP.srcport': '99999', 'TCP.dstport': '0', 'TCP.seq': '0xFFFFFFFF',
                   'TCP.ack': '0xFFFFFFFF', 'TCP.flags': '0xFF (INVALID)', 'TCP.window_size': '0', 'TCP.checksum': '0xFFFF',
                   'TCP.options': 'INVALID_OPTIONS_DATA'},
            'UDP': {'UDP.srcport': '0', 'UDP.dstport': '99999', 'UDP.checksum': '0xFFFF'},
            'ARP': {'ARP.proto.type': '0xFFFF (INVALID)', 'ARP.opcode': '0xFFFF (INVALID)',
                   'ARP.src.hw_mac': 'GG:GG:GG:GG:GG:GG', 'ARP.dst.hw_mac': 'INVALID_MAC', 'ARP.dst_ip': '999.999.999.999'},
            'ICMP': {'ICMP.type': '255 (INVALID)', 'ICMP.code': '255', 'ICMP.checksum': '0xFFFF', 'ICMP.id': '0xFFFF', 'ICMP.seq': '65535'},
            'SOMEIP': {'SOMEIP.service': '0xFFFF', 'SOMEIP.method': '0xFFFF', 'SOMEIP.client': '0xFFFF', 'SOMEIP.session': '0xFFFF',
                      'SOMEIP.proto_ver': '0xFF', 'SOMEIP.iface_ver': '0xFF', 'SOMEIP.msg_type': '0xFF (INVALID)',
                      'SOMEIP.retcode': '0xFF (E_UNKNOWN)', 'SOMEIP.payload': 'OVERFLOW'},
            'SOMEIP-SD': {'SOMEIP-SD.service': '0xFFFF', 'SOMEIP-SD.method': '0xFFFF', 'SOMEIP-SD.client': '0xFFFF', 'SOMEIP-SD.session': '0xFFFF',
                      'SOMEIP-SD.proto_ver': '0xFF', 'SOMEIP-SD.iface_ver': '0xFF', 'SOMEIP-SD.msg_type': '0xFF (INVALID)',
                      'SOMEIP-SD.retcode': '0xFF (E_UNKNOWN)', 'SOMEIP-SD.payload': 'INVALID', 'SOMEIP-SD.flags': '0xFF (INVALID)',
                      'SOMEIP-SD.entry_type': '0xFF (INVALID)', 'SOMEIP-SD.sd_service': '0xFFFF', 'SOMEIP-SD.instance_id': '0xFFFF',
                      'SOMEIP-SD.ttl': '0xFFFFFF', 'SOMEIP-SD.option_type': '0xFF (INVALID)'},
            'DOIP': {'DOIP.version': '0xFF', 'DOIP.inv_version': '0x00', 'DOIP.payload_type': '0xFFFF', 'DOIP.payload': 'INVALID'}
        };

        // 协议分层配置
        const protocolLayers = {
            'ARP': 'datalink',
            'IP': 'network',
            'ICMP': 'network',
            'TCP': 'transport',
            'UDP': 'transport',
            'SOMEIP': 'application',
            'SOMEIP-SD': 'application',
            'DOIP': 'application'
        };

        // 网卡信息
        // Dynamic NIC info - loaded from API
        let nicInfo = {};

        // 状态
        let selectedProtocols = ['ARP'];  // Support multi-select
        let legalSendMode = true;
        let fieldStates = {};

        // 初始化

        // Dynamic NIC loading from backend API
        function showToast(message, duration = 2000) {
            // 创建弹窗元素
            const toast = document.createElement('div');
            toast.style.cssText = `
                position: fixed;
                top: 50%;
                left: 50%;
                transform: translate(-50%, -50%);
                background: rgba(33, 150, 243, 0.95);
                color: white;
                padding: 20px 30px;
                border-radius: 8px;
                font-size: 16px;
                font-weight: bold;
                box-shadow: 0 4px 20px rgba(0,0,0,0.3);
                z-index: 9999;
                text-align: center;
                max-width: 400px;
                animation: fadeIn 0.3s ease;
            `;
            toast.textContent = message;

            // 添加淡入动画样式
            const style = document.createElement('style');
            style.textContent = `
                @keyframes fadeIn {
                    from { opacity: 0; transform: translate(-50%, -50%) scale(0.9); }
                    to { opacity: 1; transform: translate(-50%, -50%) scale(1); }
                }
                @keyframes fadeOut {
                    from { opacity: 1; transform: translate(-50%, -50%) scale(1); }
                    to { opacity: 0; transform: translate(-50%, -50%) scale(0.9); }
                }
            `;
            document.head.appendChild(style);

            document.body.appendChild(toast);

            // 指定时间后移除
            setTimeout(() => {
                toast.style.animation = 'fadeOut 0.3s ease';
                setTimeout(() => {
                    toast.remove();
                }, 300);
            }, duration);
        }

        // 切换字段状态
        function addLog(msg) {
            try {
                const logEl = document.getElementById('logOutput');
                if (logEl) {
                    logEl.value += msg + '\n';
                    logEl.scrollTop = logEl.scrollHeight;
                }
            } catch (e) {
                console.warn('[addLog] failed:', e);
            }
        }

        // 清空日志
        function clearLog() {
            document.getElementById('logOutput').value = '';
            addLog('[日志已清空]');
        }

        // 恢复默认值
        async function exportCapture() {
            if (capturedPackets.length === 0) {
                addLog('[导出] 没有报文可导出');
                return;
            }

            try {
                addLog('[导出] 正在导出PCAP...');
                const response = await fetch('/api/capture/export/pcap', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({})
                });

                if (response.ok) {
                    const blob = await response.blob();
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = 'capture-' + new Date().toISOString().slice(0,10) + '.pcap';
                    a.click();
                    URL.revokeObjectURL(url);
                    addLog('[导出] ✓ PCAP导出成功');
                } else {
                    const result = await response.json();
                    addLog(`[导出] ✗ 失败 - ${result.message}`);
                }
            } catch (error) {
                addLog(`[导出] ✗ 错误 - ${error.message}`);
            }
        }

        // 导出CSV
        async function exportCSV() {
            if (capturedPackets.length === 0) {
                addLog('[导出] 没有报文可导出');
                return;
            }

            // CSV导出功能暂未实现,生成简单的CSV
            try {
                addLog('[导出] 正在生成CSV...');

                let csv = '序号,时间,源IP,目标IP,源MAC,目标MAC,源端口,目标端口,协议,信息,长度,CRL/DRs,国家\n';
                capturedPackets.forEach((pkt, index) => {
                    csv += `${index+1},${pkt.time || ''},${pkt.src_ip || ''},${pkt.dst_ip || ''},${pkt.src_mac || ''},${pkt.dst_mac || ''},${pkt.src_port || ''},${pkt.dst_port || ''},${pkt.protocol || ''},${pkt.info || ''},${pkt.length || 0},${pkt.crl_drs || ''},${pkt.country || ''}\n`;
                });

                const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'capture-' + new Date().toISOString().slice(0,10) + '.csv';
                a.click();
                URL.revokeObjectURL(url);
                addLog('[导出] ✓ CSV导出成功');
            } catch (error) {
                addLog(`[导出] ✗ 错误 - ${error.message}`);
            }
        }

        // 捕获控制函数
        function formatMac(mac) {
            if (!mac || mac === '-') return '00:00:00:00:00:00';
            return mac.toLowerCase();
        }

        // 辅助函数:获取帧中的协议列表
        function getProtocolsInFrame(pkt) {
            const protos = ['eth'];
            if (pkt.src_ip && pkt.src_ip !== '-') protos.push('ip');
            if (pkt.protocol) {
                const proto = pkt.protocol.toLowerCase();
                if (proto === 'someip-sd') {
                    protos.push('someip:sd');
                } else {
                    protos.push(proto);
                }
            }
            return protos.join(':');
        }

        // 辅助函数:获取以太网类型
        function getEthernetType(protocol) {
            const types = {
                'IP': 'IPv4',
                'TCP': 'IPv4',
                'UDP': 'IPv4',
                'ICMP': 'IPv4',
                'ARP': 'ARP',
                'SOMEIP': 'IPv4',
                'SOMEIP-SD': 'IPv4',
                'DOIP': 'IPv4'
            };
            return types[protocol] || 'IPv4';
        }

        // 辅助函数:获取以太网类型十六进制
        function getEtherTypeHex(protocol) {
            if (protocol === 'ARP') return '0806';
            return '0800';
        }

        // 辅助函数:获取 IP 协议名称
        function getIPProtocolName(protocol) {
            const names = {
                'TCP': 'TCP',
                'UDP': 'UDP',
                'ICMP': 'ICMP',
                'SOMEIP': 'UDP',
                'SOMEIP-SD': 'UDP',
                'DOIP': 'TCP'
            };
            return names[protocol] || protocol;
        }

        // 辅助函数:获取 IP 协议号
        function getIPProtocolNum(protocol) {
            const nums = {
                'TCP': 6,
                'UDP': 17,
                'ICMP': 1,
                'SOMEIP': 17,
                'SOMEIP-SD': 17,
                'DOIP': 6
            };
            return nums[protocol] || 0;
        }

        // 辅助函数:格式化十六进制数据
        function formatHexData(rawBytes, offset) {
            const start = offset * 2;
            const data = rawBytes.substring(start, start + 64);
            let result = '';
            for (let i = 0; i < data.length; i += 2) {
                result += data.substring(i, i + 2) + ' ';
            }
            return result.trim() + (data.length < rawBytes.length - start ? '...' : '');
        }

        // 渲染 Hex 视图
        function parseTCPOptions(optionsHex) {
            const options = [];
            let offset = 0;

            const optionNames = {
                0: 'End of Option List (EOL)',
                1: 'No-Operation (NOP)',
                2: 'Maximum Segment Size (MSS)',
                3: 'Window Scale',
                4: 'SACK Permitted',
                5: 'SACK',
                8: 'Timestamps',
                14: 'Alternate Checksum Request',
                15: 'Alternate Checksum Data',
                34: 'Quick-Start Response'
            };

            while (offset < optionsHex.length) {
                const kind = parseInt(optionsHex.substring(offset, offset + 2), 16);
                offset += 2;

                if (kind === 0) {
                    // End of Option List
                    options.push({ kind: 0, name: optionNames[0], value: '' });
                    break;
                } else if (kind === 1) {
                    // NOP - 无长度字段
                    options.push({ kind: 1, name: optionNames[1], value: '' });
                } else {
                    // 其他选项有长度字段
                    if (offset + 2 > optionsHex.length) break;
                    const length = parseInt(optionsHex.substring(offset, offset + 2), 16);
                    offset += 2;

                    if (length < 2 || offset + (length - 2) * 2 > optionsHex.length) break;

                    const dataHex = optionsHex.substring(offset, offset + (length - 2) * 2);
                    offset += (length - 2) * 2;

                    let value = '';
                    switch (kind) {
                        case 2:  // MSS
                            value = parseInt(dataHex, 16) + ' bytes';
                            break;
                        case 3:  // Window Scale
                            value = 'shift count: ' + parseInt(dataHex, 16);
                            break;
                        case 4:  // SACK Permitted
                            value = 'allowed';
                            break;
                        case 5:  // SACK
                            value = dataHex.match(/.{8}/g).map(b => '0x' + b).join(', ');
                            break;
                        case 8:  // Timestamps
                            if (dataHex.length >= 16) {
                                const tsVal = parseInt(dataHex.substring(0, 8), 16);
                                const tsEcr = parseInt(dataHex.substring(8, 16), 16);
                                value = `TSval=${tsVal}, TSecr=${tsEcr}`;
                            }
                            break;
                        default:
                            value = '0x' + dataHex;
                    }

                    options.push({
                        kind: kind,
                        name: optionNames[kind] || `Option Kind ${kind}`,
                        value: value
                    });
                }
            }

            return options;
        }

        // 格式化十六进制字符串(添加空格分隔)
        function formatHexString(hex, bytesPerLine) {
            let result = '';
            for (let i = 0; i < hex.length; i += 2) {
                if (i > 0 && i % (bytesPerLine * 2) === 0) result += '\n';
                result += hex.substring(i, i + 2) + ' ';
            }
            return result.trim();
        }

        // 展开/折叠协议树节点
        function toggleExpand(targetId, expander) {
            const target = document.getElementById(targetId);
            if (target) {
                target.classList.toggle('collapsed');
                expander.classList.toggle('collapsed');
                expander.textContent = target.classList.contains('collapsed') ? '▶' : '▼';
            }
        }

