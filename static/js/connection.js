        function updateSendModeText() {
            const select = document.getElementById('sendModeSelect');
            const textSpan = document.getElementById('sendModeText');
            const adminHint = document.getElementById('adminHint');
            const mode = select.value;

            const modeTexts = {
                'simulate': '纯模拟',
                'raw': '原始报文',
                'socket': '普通Socket(推荐)',
                'npcap': 'Npcap模式'
            };

            textSpan.textContent = modeTexts[mode];
            textSpan.className = 'mode-text mode-' + mode;

            if (adminHint) {
                if (mode === 'raw' || mode === 'npcap') {
                    adminHint.style.display = 'inline';
                } else {
                    adminHint.style.display = 'none';
                }
            }
        }

        // 刷新网卡
        async function refreshNic() {
            addLog('[NIC] 正在刷新网卡列表...');
            await loadNics(); // Reload from API (defined in utils.js)
            updateNicInfo(); // 确保更新显示
            addLog('[NIC] 网卡列表已刷新');
        }

        // 选择协议 (跨层多选，同层单选)
        function toggleProtocol(protocol) {
            const layer = protocolLayers[protocol];
            const index = selectedProtocols.indexOf(protocol);
            
            // ========== 统一的协议层级逻辑 ==========
            
            // 定义层级关系
            const layerOrder = {
                'datalink': 1,   // ARP
                'network': 2,    // IP, ICMP
                'transport': 3,  // TCP, UDP
                'application': 4 // SOMEIP, SOMEIP-SD, DOIP
            };
            
            // 获取当前选中协议的最高层级
            let currentMaxLayer = 1;
            selectedProtocols.forEach(p => {
                const l = layerOrder[protocolLayers[p]] || 1;
                if (l > currentMaxLayer) currentMaxLayer = l;
            });
            
            // 获取要选择的协议的层级
            const targetLayer = layerOrder[layer] || 1;
            
            if (index > -1) {
                // ========== 取消选择 ==========
                if (selectedProtocols.length > 1) {
                    selectedProtocols.splice(index, 1);
                    
                    // 取消 SOMEIP-SD 时，同时取消 UDP
                    if (protocol === 'SOMEIP-SD') {
                        const udpIndex = selectedProtocols.indexOf('UDP');
                        if (udpIndex > -1) {
                            selectedProtocols.splice(udpIndex, 1);
                        }
                    }
                }
            } else {
                // ========== 选择新协议 ==========
                
                // 规则1: 如果已有高层协议(应用层/传输层)，选择ICMP(网络层)时，清除所有高层
                if (protocol === 'ICMP' && currentMaxLayer > 2) {
                    selectedProtocols = selectedProtocols.filter(p => {
                        const pLayer = layerOrder[protocolLayers[p]] || 1;
                        return pLayer <= 2; // 只保留数据链路层和网络层
                    });
                }
                
                // 规则2: 如果已有ICMP，选择高层协议时，自动取消ICMP
                if (targetLayer > 2 && selectedProtocols.includes('ICMP')) {
                    const icmpIndex = selectedProtocols.indexOf('ICMP');
                    if (icmpIndex > -1) {
                        selectedProtocols.splice(icmpIndex, 1);
                    }
                }
                
                // 规则3: 同层单选 - 移除同层的其他协议
                selectedProtocols = selectedProtocols.filter(p => protocolLayers[p] !== layer);
                
                // 添加新协议
                selectedProtocols.push(protocol);
                
                // 规则4: 选应用层(SOMEIP/DOIP/SOMEIP-SD)时，自动添加IP
                if (targetLayer === 4 && !selectedProtocols.includes('IP')) {
                    selectedProtocols.push('IP');
                }
                
                // 规则5: 选传输层(TCP/UDP)或ICMP时，自动添加IP
                if ((protocol === 'TCP' || protocol === 'UDP' || protocol === 'ICMP') && !selectedProtocols.includes('IP')) {
                    selectedProtocols.push('IP');
                }
                
                // 规则6: SOMEIP-SD 特殊处理 - 只保留UDP，清除TCP
                if (protocol === 'SOMEIP-SD') {
                    // 清除TCP
                    const tcpIndex = selectedProtocols.indexOf('TCP');
                    if (tcpIndex > -1) {
                        selectedProtocols.splice(tcpIndex, 1);
                    }
                    // 添加UDP（如果不存在）
                    if (!selectedProtocols.includes('UDP')) {
                        selectedProtocols.push('UDP');
                    }
                    showToast('SOME/IP-SD 依赖 UDP 传输，已自动选中 UDP 协议', 2000);
                }
                
                // 规则7: SOMEIP/DOIP 提示需要传输层
                if (protocol === 'SOMEIP' || protocol === 'DOIP') {
                    const hasTCP = selectedProtocols.includes('TCP');
                    const hasUDP = selectedProtocols.includes('UDP');
                    if (!hasTCP && !hasUDP) {
                        showToast(`${protocol} 需要选择传输层协议（TCP或UDP），请手动选择`, 3000);
                    }
                }
            }
            
            // 更新按钮样式
            document.querySelectorAll('.protocol-btn').forEach(btn => {
                btn.classList.toggle('active', selectedProtocols.includes(btn.dataset.protocol));
            });

            // 清除字段状态并重新渲染
            fieldStates = {};
            renderFieldButtons();
            
            console.log('[Protocol] Selected:', selectedProtocols);
        }

        // 显示提示弹窗
        function assemblePacket() {
            // Legacy function - now just logs
            const protocol = selectedProtocols[0] || "ARP";
            const illegalFields = Object.keys(fieldStates).filter(f => fieldStates[f] && !legalSendMode);
            addLog(`[组装] ${selectedProtocols.join(",")} - 点击发送按钮发送报文`);
        }

        // 存储TCP连接ID
        let tcpConnId = null;

        // 发送报文
        async function sendPacket() {
            const count = parseInt(document.getElementById('sendCount').value) || 1;
            const interval = parseInt(document.getElementById('sendInterval').value) || 100;
            const targetIp = document.getElementById('targetIp').value || '192.168.1.1';
            const targetPort = parseInt(document.getElementById('targetPort').value) || 80;
            const nic = document.getElementById('nicSelect').value;
            const mode = document.getElementById('sendModeSelect').value;
            const protocol = selectedProtocols[0] || 'ARP';
            const illegalFields = Object.keys(fieldStates).filter(f => fieldStates[f] && !legalSendMode);

            const modeStr = illegalFields.length > 0 ? '混合模式' : '合法模式';

            addLog(`[发送请求] ${protocol} ${modeStr} - 次数:${count} 间隔:${interval}ms`);

            // Build packet data based on selected protocol
            let packetData = {};
            try {
                packetData = buildPacketData(protocol, illegalFields);
            } catch (e) {
                addLog(`[发送] 构建报文数据失败: ${e.message}`);
                packetData = {};
            }

            try {
                let response;
                const payload = {
                    target_ip: targetIp,
                    target_port: targetPort,
                    mode: mode,
                    interface: nic,
                    count: count,
                    interval_ms: interval,
                    packet_data: packetData
                };

                // Add conn_id for TCP if available
                if (protocol === 'TCP' && tcpConnId) {
                    payload.conn_id = tcpConnId;
                }

                switch (protocol) {
                    case 'TCP':
                        if (tcpConnId) {
                            // 使用已有连接发送攻击包
                            const tcpPayload = {
                                conn_id: tcpConnId,
                                packet_data: packetData,
                                count: count,
                                interval: interval,
                                target_ip: targetIp,
                                target_port: targetPort,
                                mode: mode,
                                interface: nic
                            };
                            response = await fetch('/api/tcp/attack', {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify(tcpPayload)
                            });
                        } else {
                            // 无连接时直接发送
                            response = await fetch('/api/tcp/send', {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify(payload)
                            });
                        }
                        break;
                    case 'UDP':
                        response = await fetch('/api/udp/send', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify(payload)
                        });
                        break;
                    case 'ICMP':
                        response = await fetch('/api/icmp/send', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({
                                target_ip: targetIp,
                                mode: mode,
                                interface: nic,
                                count: count,
                                interval_ms: interval,
                                packet_data: packetData
                            })
                        });
                        break;
                    case 'ARP':
                        response = await fetch('/api/scapy/send', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({
                                packet_hex: buildPacketHex('ARP', packetData),
                                interface: nic,
                                count: count,
                                interval: interval
                            })
                        });
                        break;
                    default:
                        // 其他协议使用 scapy 发送
                        response = await fetch('/api/scapy/build', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({
                                protocol: protocol,
                                fields: packetData
                            })
                        });
                        
                        const buildResult = await response.json();
                        if (!buildResult.success) {
                            addLog(`[发送] ${protocol} 构建报文失败`);
                            return;
                        }
                        
                        // 发送构建好的报文
                        response = await fetch('/api/scapy/send', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({
                                packet_hex: buildResult.packet_hex,
                                interface: nic,
                                count: count,
                                interval: interval
                            })
                        });
                        break;
                }

                const result = await response.json();

                if (result.success) {
                    addLog(`[发送] ✓ 成功 - 已发送 ${result.sent || count} 个报文`);
                    if (result.message) {
                        addLog(`[发送] ${result.message}`);
                    }
                } else {
                    addLog(`[发送] ✗ 失败 - ${result.message}`);
                }
            } catch (error) {
                addLog(`[发送] ✗ 错误 - ${error.message}`);
            }
        }

        // Build packet data from field values
        async function oneClickHandshake() {
            const handshakeBtn = document.getElementById('handshakeBtn');
            const targetIp = document.getElementById('targetIp').value || '192.168.1.1';
            const targetPort = parseInt(document.getElementById('targetPort').value) || 80;
            const mode = document.getElementById('sendModeSelect').value;
            const nic = document.getElementById('nicSelect').value;
            
            // 如果已有连接，则断开
            if (tcpConnId) {
                addLog(`[TCP握手] 正在断开连接...`);
                try {
                    const response = await fetch('/api/tcp/close', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            conn_id: tcpConnId
                        })
                    });
                    
                    const result = await response.json();
                    if (result.success) {
                        tcpConnId = null;
                        if (handshakeBtn) {
                            handshakeBtn.classList.remove('connected');
                        }
                        addLog(`[TCP握手] ✓ 已断开连接`);
                    } else {
                        addLog(`[TCP握手] ✗ 断开失败 - ${result.message}`);
                    }
                } catch (error) {
                    addLog(`[TCP握手] ✗ 断开错误 - ${error.message}`);
                }
                return;
            }
            
            // 建立新连接
            addLog(`[TCP握手] 正在连接 ${targetIp}:${targetPort} (模式: ${mode})...`);
            
            try {
                const response = await fetch('/api/tcp/handshake', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        target_ip: targetIp,
                        target_port: targetPort,
                        mode: mode,
                        interface: nic
                    })
                });
                
                const result = await response.json();
                if (result.success) {
                    tcpConnId = result.conn_id;
                    // 更新按钮状态为已连接（黄色高亮）
                    if (handshakeBtn) {
                        handshakeBtn.classList.add('connected');
                    }
                    addLog(`[TCP握手] ✓ 成功 - 连接ID: ${result.conn_id}, 状态: ${result.state}`);
                    if (result.message) {
                        addLog(`[TCP握手] ${result.message}`);
                    }
                } else {
                    addLog(`[TCP握手] ✗ 失败 - ${result.message}`);
                }
            } catch (error) {
                addLog(`[TCP握手] ✗ 错误 - ${error.message}`);
            }
        }

        // 预留功能（待实现）
