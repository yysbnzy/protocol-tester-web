// === Top-level variables ===
        let nicInfo = {};

        // 状态
        let selectedProtocols = ['ARP'];  // Support multi-select
        let legalSendMode = true;
        let fieldStates = {};




        // 初始化
        
        // Dynamic NIC loading from backend API
        async function loadNics() {
            try {
                console.log('[NIC] Loading from API...');
                const response = await fetch('/api/nics');
                const data = await response.json();
                console.log('[NIC] Response:', data);
                
                if (data.nics && data.nics.length > 0) {
                    // Build nicInfo from API response
                    nicInfo = {};
                    data.nics.forEach(nic => {
                        nicInfo[nic.name] = {
                            ip: nic.ip || 'N/A',
                            mac: nic.mac || 'N/A'
                        };
                    });
                    
                    // Update select dropdown
                    const select = document.getElementById('nicSelect');
                    if (select) {
                        select.innerHTML = '';
                        data.nics.forEach(nic => {
                            const option = document.createElement('option');
                            option.value = nic.name;
                            option.textContent = nic.name;
                            select.appendChild(option);
                        });
                        
                        // Update display
                        updateNicInfo();
                        console.log('[NIC] Loaded', data.nics.length, 'NICs');
                    }
                } else {
                    console.warn('[NIC] No NICs returned from API');
                    document.getElementById('nicInfo').textContent = '未找到可用网卡';
                    // 添加一个默认选项
                    if (select) {
                        select.innerHTML = '<option value="">无可用网卡</option>';
                    }
                }
            } catch (error) {
                console.error('[NIC] Failed to load:', error);
                document.getElementById('nicInfo').textContent = '加载网卡失败，请检查后端服务';
                // 添加一个默认选项
                if (select) {
                    select.innerHTML = '<option value="">加载失败</option>';
                }
            }
        }

        let legalDefaultsFromDB = {};
        let illegalDefaultsFromDB = {};

        
        async function loadDefaultValues() {
            try {
                console.log('[Defaults] Loading from API...');
                
                if (data.legal) {
                    legalDefaultsFromDB = data.legal;
                    console.log('[Defaults] Loaded legal defaults from DB');
                }
                if (data.illegal) {
                    illegalDefaultsFromDB = data.illegal;
                    console.log('[Defaults] Loaded illegal defaults from DB');
                }
            } catch (error) {
                console.warn('[Defaults] Failed to load from API, using hardcoded defaults:', error);
                // 使用硬编码默认值作为后备
                legalDefaultsFromDB = legalDefaults;
                illegalDefaultsFromDB = illegalDefaults;
            }
        }


        async function loadNics() {
            try {
                console.log('[NIC] Loading from API...');
                console.log('[NIC] Response:', data);
                
                if (data.nics && data.nics.length > 0) {
                    // Build nicInfo from API response
                    nicInfo = {};
                    data.nics.forEach(nic => {
                        nicInfo[nic.name] = {
                            ip: nic.ip || 'N/A',
                            mac: nic.mac || 'N/A'
                        };
                    });
                    
                    // Update select dropdown
                    if (select) {
                        select.innerHTML = '';
                        data.nics.forEach(nic => {
                            option.value = nic.name;
                            option.textContent = nic.name;
                            select.appendChild(option);
                        });
                        
                        // Update display
                        updateNicInfo();
                        console.log('[NIC] Loaded', data.nics.length, 'NICs');
                    }
                } else {
                    console.warn('[NIC] No NICs returned from API');
                    document.getElementById('nicInfo').textContent = '未找到可用网卡';
                    // 添加一个默认选项
                    if (select) {
                        select.innerHTML = '<option value="">无可用网卡</option>';
                    }
                }
            } catch (error) {
                console.error('[NIC] Failed to load:', error);
                document.getElementById('nicInfo').textContent = '加载网卡失败，请检查后端服务';
                // 添加一个默认选项
                if (select) {
                    select.innerHTML = '<option value="">加载失败</option>';
                }
            }
        }
        
        function updateNicInfo() {
            const nic = select ? select.value : '';
            const info = nicInfo[nic] || {ip: 'N/A', mac: 'N/A'};
            const el = document.getElementById('nicInfo');
            if (el) {
                el.textContent = 'IP: ' + info.ip + ' | MAC: ' + info.mac;
            }
            
            // 同步IP和MAC到协议字段
            if (info.ip !== 'N/A') {
                // 同步到IP协议的src字段
                const ipSrcInput = document.getElementById('legal-IP-src');
                if (ipSrcInput) {
                    ipSrcInput.value = info.ip;
                }
            }
            if (info.mac !== 'N/A') {
                // 同步到ARP协议的src.hw_mac字段
                const arpMacInput = document.getElementById('legal-ARP-src.hw_mac');
                if (arpMacInput) {
                    arpMacInput.value = info.mac;
                }
            }
        }

        // Bug Fix 4: 从后端API加载默认值
        
        async function loadDefaultValues() {
            try {
                console.log('[Defaults] Loading from API...');
                
                if (data.legal) {
                    legalDefaultsFromDB = data.legal;
                    console.log('[Defaults] Loaded legal defaults from DB');
                }
                if (data.illegal) {
                    illegalDefaultsFromDB = data.illegal;
                    console.log('[Defaults] Loaded illegal defaults from DB');
                }
            } catch (error) {
                console.warn('[Defaults] Failed to load from API, using hardcoded defaults:', error);
                // 使用硬编码默认值作为后备
                legalDefaultsFromDB = legalDefaults;
                illegalDefaultsFromDB = illegalDefaults;
            }
        }
        
        // 获取默认值的辅助函数
        function getLegalDefault(protocol, field) {
            return legalDefaultsFromDB[protocol]?.[field] || legalDefaults[protocol]?.[field] || '0';
        }
        
        function getIllegalDefault(protocol, field) {
            return illegalDefaultsFromDB[protocol]?.[field] || illegalDefaults[protocol]?.[field] || 'INVALID';
        }

        function resetDefaults() {
            // 重置所有输入框为默认值
            Object.keys(protocolFields).forEach(protocol => {
                protocolFields[protocol].forEach(field => {
                    // 合法值
                    const legalInput = document.getElementById(`legal-${protocol}-${field}`);
                    if (legalInput) {
                        legalInput.value = legalDefaults[protocol]?.[field] || '0';
                    }
                    // 非法值
                    const illegalInput = document.getElementById(`illegal-${protocol}-${field}`);
                    if (illegalInput) {
                        illegalInput.value = illegalDefaults[protocol]?.[field] || 'INVALID';
                    }
                });
            });

            // 重置发送次数和间隔
            document.getElementById('sendCount').value = '1';
            document.getElementById('sendInterval').value = '100';

            // 重置字段状态
            legalSendMode = true;
            updateLegalSendBtn();
            Object.keys(fieldStates).forEach(k => fieldStates[k] = false);
            updateFieldButtons();

            // 清空报文输出
            const captureOutput = document.getElementById('captureOutput');
            if (captureOutput) {
                captureOutput.value = '';
            }

            addLog('[恢复默认] 所有字段已重置为默认值');
        }

        // 重置合法值为默认值
        function resetLegalValues() {
            Object.keys(protocolFields).forEach(protocol => {
                protocolFields[protocol].forEach(field => {
                    const input = document.getElementById(`legal-${protocol}-${field}`);
                    if (input) {
                        input.value = legalDefaults[protocol]?.[field] || '0';
                    }
                });
            });
            addLog('[合法值] 已重置为默认值');
        }

        // 清空合法值
        function clearLegalValues() {
            Object.keys(protocolFields).forEach(protocol => {
                protocolFields[protocol].forEach(field => {
                    if (input) {
                        input.value = '';
                    }
                });
            });
            addLog('[合法值] 已清空');
        }

        // 重置非法值为默认值
        function resetIllegalValues() {
            Object.keys(protocolFields).forEach(protocol => {
                protocolFields[protocol].forEach(field => {
                    if (input) {
                        input.value = illegalDefaults[protocol]?.[field] || 'INVALID';
                    }
                });
            });
            addLog('[非法值] 已重置为默认值');
        }

        // 清空非法值
        function clearIllegalValues() {
            Object.keys(protocolFields).forEach(protocol => {
                protocolFields[protocol].forEach(field => {
                    if (input) {
                        input.value = '';
                    }
                });
            });
            addLog('[非法值] 已清空');
        }

        // 保存指定协议的合法值为新的默认值
        function saveProtocolLegalValues(protocol) {
            protocolFields[protocol].forEach(field => {
                if (input) {
                    legalDefaults[protocol][field] = input.value;
                }
            });
            addLog(`[合法值] ${protocol} 已保存为新的默认值`);
        }

        // 保存指定协议的非法值为新的默认值
        function saveProtocolIllegalValues(protocol) {
            protocolFields[protocol].forEach(field => {
                if (input) {
                    illegalDefaults[protocol][field] = input.value;
                }
            });
            addLog(`[非法值] ${protocol} 已保存为新的默认值`);
        }

        // 重置指定协议的合法值
        function resetProtocolLegalValues(protocol) {
            protocolFields[protocol].forEach(field => {
                if (input) {
                    input.value = legalDefaults[protocol]?.[field] || '0';
                }
            });
            addLog(`[合法值] ${protocol} 已重置为默认值`);
        }

        // 清空指定协议的合法值
        function clearProtocolLegalValues(protocol) {
            protocolFields[protocol].forEach(field => {
                if (input) {
                    input.value = '';
                }
            });
            addLog(`[合法值] ${protocol} 已清空`);
        }

        // 重置指定协议的非法值
        function resetProtocolIllegalValues(protocol) {
            protocolFields[protocol].forEach(field => {
                if (input) {
                    input.value = illegalDefaults[protocol]?.[field] || 'INVALID';
                }
            });
            addLog(`[非法值] ${protocol} 已重置为默认值`);
        }

        // 清空指定协议的非法值
        function clearProtocolIllegalValues(protocol) {
            protocolFields[protocol].forEach(field => {
                if (input) {
                    input.value = '';
                }
            });
            addLog(`[非法值] ${protocol} 已清空`);
        }

        // 一键TCP握手
