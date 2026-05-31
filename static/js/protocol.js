// === Top-level variables ===
        const protocolFields = {
            'ARP': ['ARP.proto.type', 'ARP.opcode', 'ARP.src.hw_mac', 'ARP.dst.hw_mac'],
            'IP': ['IP.version', 'IP.tos', 'IP.id', 'IP.ttl', 'IP.checksum', 'IP.src', 'IP.dst'],
            'TCP': ['TCP.srcport', 'TCP.dstport', 'TCP.seq', 'TCP.ack', 'TCP.flags', 'TCP.window_size', 'TCP.checksum', 'TCP.options'],
            'UDP': ['UDP.srcport', 'UDP.dstport', 'UDP.checksum'],
            'ICMP': ['ICMP.type', 'ICMP.code', 'ICMP.checksum', 'ICMP.id', 'ICMP.seq'],
            'SOMEIP': ['SOMEIP.service', 'SOMEIP.method', 'SOMEIP.client', 'SOMEIP.session',
                      'SOMEIP.proto_ver', 'SOMEIP.iface_ver', 'SOMEIP.msg_type', 'SOMEIP.retcode', 'SOMEIP.payload'],
            'SOMEIP-SD': ['SOMEIP-SD.service_id', 'SOMEIP-SD.method_id', 'SOMEIP-SD.client_id', 'SOMEIP-SD.session_id', 'SOMEIP-SD.proto_ver', 'SOMEIP-SD.iface_ver', 'SOMEIP-SD.msg_type', 'SOMEIP-SD.retcode', 'SOMEIP-SD.payload', 'SOMEIP-SD.flags', 'SOMEIP-SD.entry_type', 'SOMEIP-SD.sd_service_id', 'SOMEIP-SD.instance_id', 'SOMEIP-SD.ttl', 'SOMEIP-SD.option_type'],
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
                   'ARP.src.hw_mac': '00:11:22:33:44:55', 'ARP.dst.hw_mac': '00:00:00:00:00:00'},
            'ICMP': {'ICMP.type': '8 (Echo Request)', 'ICMP.code': '0', 'ICMP.checksum': '0x0000', 'ICMP.id': '0x1234', 'ICMP.seq': '1'},
            'SOMEIP': {'SOMEIP.service': '0x1234', 'SOMEIP.method': '0x5678', 'SOMEIP.client': '0x0001', 'SOMEIP.session': '0x0001',
                      'SOMEIP.proto_ver': '0x01', 'SOMEIP.iface_ver': '0x01', 'SOMEIP.msg_type': '0x00 (REQUEST)',
                      'SOMEIP.retcode': '0x00 (E_OK)', 'SOMEIP.payload': '0xDEADBEEF'},
            'SOMEIP-SD': {'SOMEIP-SD.service_id': '0xFFFF', 'SOMEIP-SD.method_id': '0x8100', 'SOMEIP-SD.client_id': '0x0000', 'SOMEIP-SD.session_id': '0x0001',
                      'SOMEIP-SD.proto_ver': '0x01', 'SOMEIP-SD.iface_ver': '0x01', 'SOMEIP-SD.msg_type': '0x02 (NOTIFICATION)',
                      'SOMEIP-SD.retcode': '0x00 (E_OK)', 'SOMEIP-SD.payload': '-payload-sd-', 'SOMEIP-SD.flags': '0xC0', 'SOMEIP-SD.entry_type': '0x01 (Offer)',
                      'SOMEIP-SD.sd_service_id': '0x1234', 'SOMEIP-SD.instance_id': '0x0001', 'SOMEIP-SD.ttl': '3', 'SOMEIP-SD.option_type': '0x04 (IPv4 Endpoint)'},
            'DOIP': {'DOIP.version': '0x02', 'DOIP.inv_version': '0xFD', 'DOIP.payload_type': '0x0001', 'DOIP.payload': '0x00'}
        };

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
                'service_id': { offset: 24, bitStart: 0, bitLen: 16, name: 'Service ID' },
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
                   'ARP.src.hw_mac': 'GG:GG:GG:GG:GG:GG', 'ARP.dst.hw_mac': 'INVALID_MAC'},
            'ICMP': {'ICMP.type': '255 (INVALID)', 'ICMP.code': '255', 'ICMP.checksum': '0xFFFF', 'ICMP.id': '0xFFFF', 'ICMP.seq': '65535'},
            'SOMEIP': {'SOMEIP.service': '0xFFFF', 'SOMEIP.method': '0xFFFF', 'SOMEIP.client': '0xFFFF', 'SOMEIP.session': '0xFFFF',
                      'SOMEIP.proto_ver': '0xFF', 'SOMEIP.iface_ver': '0xFF', 'SOMEIP.msg_type': '0xFF (INVALID)',
                      'SOMEIP.retcode': '0xFF (E_UNKNOWN)', 'SOMEIP.payload': 'OVERFLOW'},
            'SOMEIP-SD': {'SOMEIP-SD.service_id': '0xFFFF', 'SOMEIP-SD.method_id': '0xFFFF', 'SOMEIP-SD.client_id': '0xFFFF', 'SOMEIP-SD.session_id': '0xFFFF',
                      'SOMEIP-SD.proto_ver': '0xFF', 'SOMEIP-SD.iface_ver': '0xFF', 'SOMEIP-SD.msg_type': '0xFF (INVALID)',
                      'SOMEIP-SD.retcode': '0xFF (E_UNKNOWN)', 'SOMEIP-SD.payload': 'INVALID', 'SOMEIP-SD.flags': '0xFF (INVALID)',
                      'SOMEIP-SD.entry_type': '0xFF (INVALID)', 'SOMEIP-SD.sd_service_id': '0xFFFF', 'SOMEIP-SD.instance_id': '0xFFFF',
                      'SOMEIP-SD.ttl': '0xFFFFFF', 'SOMEIP-SD.option_type': '0xFF (INVALID)'},
            'DOIP': {'DOIP.version': '0xFF', 'DOIP.inv_version': '0x00', 'DOIP.payload_type': '0xFFFF', 'DOIP.payload': 'INVALID'}
        };

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


        function renderFieldButtons() {
            const container = document.getElementById('fieldButtons');
            container.innerHTML = '';
            // Bug Fix 2: 不要在这里清空fieldStates，保留用户选择的字段状态
            // 但如果协议被取消选择，应该清除该协议的字段状态
            
            console.log('[DEBUG] Rendering fields for', selectedProtocols);
            
            if (selectedProtocols.length === 0) {
                container.innerHTML = '<div style="padding:10px;color:#999;">Select at least one protocol</div>';
                return;
            }
            
            // Bug Fix 2: 清理不再选中的协议的字段状态
            Object.keys(fieldStates).forEach(field => {
                let fieldBelongsToSelected = false;
                for (const protocol of selectedProtocols) {
                    if (protocolFields[protocol] && protocolFields[protocol].includes(field)) {
                        fieldBelongsToSelected = true;
                        break;
                    }
                }
                if (!fieldBelongsToSelected) {
                    delete fieldStates[field];
                }
            });
            
            // Fixed protocol order
            const protocolOrder = ['ARP', 'IP', 'ICMP', 'TCP', 'UDP', 'SOMEIP', 'SOMEIP-SD', 'DOIP'];
            
            // Display fields in fixed protocol order
            protocolOrder.forEach(protocol => {
                if (selectedProtocols.includes(protocol)) {
                    const fields = protocolFields[protocol] || [];
                    if (fields.length > 0) {
                        // Protocol label
                        const label = document.createElement('div');
                        // SOMEIP-SD 使用更小的字体
                        const fontSize = protocol === 'SOMEIP-SD' ? '9px' : '10px';
                        label.style.cssText = `font-size:${fontSize};color:#2196f3;padding:2px 0;margin:5px 0;text-align:center;`;
                        label.textContent = `—${protocol}—`;
                        container.appendChild(label);
                        
                        // Fields for this protocol
                        fields.forEach(field => {
                            // Bug Fix 2: 确保字段状态初始化
                            if (!(field in fieldStates)) {
                                fieldStates[field] = false;
                            }
                            const btn = document.createElement('button');
                            btn.className = 'field-btn';
                            btn.textContent = field;
                            // Bug Fix 2: 恢复字段按钮的选中状态
                            if (fieldStates[field]) {
                                btn.classList.add('selected'); // 如果有选中样式的话
                            }
                            btn.onclick = () => toggleField(field);
                            container.appendChild(btn);
                        });
                    }
                }
            });
            
            // Update values display - Bug Fix 2: 强制更新显示
            updateValuesDisplay();
        }
        
        function updateValuesDisplay() {
            // Show values for all selected protocols
            document.querySelectorAll('.protocol-group').forEach(group => {
                const title = group.querySelector('h4');
                if (title) {
                    const protocol = title.textContent.replace('-', '');
                    group.style.display = selectedProtocols.includes(protocol) ? 'block' : 'none';
                }
            });
        }

        // 渲染输入框
        function renderValueInputs() {
            const legalContainer = document.getElementById('legalValues');
            const illegalContainer = document.getElementById('illegalValues');
            legalContainer.innerHTML = '';
            illegalContainer.innerHTML = '';

            Object.keys(protocolFields).forEach(protocol => {
                // 合法值
                const legalGroup = createFieldGroup(protocol, 'legal');
                legalContainer.appendChild(legalGroup);

                // 非法值
                const illegalGroup = createFieldGroup(protocol, 'illegal');
                illegalContainer.appendChild(illegalGroup);
            });
        }

        function createFieldGroup(protocol, type) {
            const group = document.createElement('div');
            group.className = 'protocol-group';

            const titleRow = document.createElement('div');
            titleRow.className = 'protocol-title-row';

            title.textContent = `-${protocol}`;
            titleRow.appendChild(title);

            // 在合法值和非法值区域都添加操作按钮
            if (type === 'legal' || type === 'illegal') {
                const actions = document.createElement('div');
                actions.className = 'protocol-actions';

                // 保存按钮
                const saveLink = document.createElement('span');
                saveLink.className = 'text-link';
                saveLink.textContent = '保存';
                if (type === 'legal') {
                    saveLink.onclick = () => saveProtocolLegalValues(protocol);
                } else {
                    saveLink.onclick = () => saveProtocolIllegalValues(protocol);
                }

                const resetLink = document.createElement('span');
                resetLink.className = 'text-link';
                resetLink.textContent = '默认';
                if (type === 'legal') {
                    resetLink.onclick = () => resetProtocolLegalValues(protocol);
                } else {
                    resetLink.onclick = () => resetProtocolIllegalValues(protocol);
                }

                const clearLink = document.createElement('span');
                clearLink.className = 'text-link';
                clearLink.textContent = '清空';
                if (type === 'legal') {
                    clearLink.onclick = () => clearProtocolLegalValues(protocol);
                } else {
                    clearLink.onclick = () => clearProtocolIllegalValues(protocol);
                }

                actions.appendChild(saveLink);
                actions.appendChild(document.createTextNode(' '));
                actions.appendChild(resetLink);
                actions.appendChild(document.createTextNode(' '));
                actions.appendChild(clearLink);
                titleRow.appendChild(actions);
            }

            group.appendChild(titleRow);

            
            // SOME/IP-SD 固定值字段（不可编辑）
            const someipSdFixedFields = ['service_id', 'method_id', 'client_id', 'proto_ver', 'iface_ver', 'msg_type', 'retcode'];
            
            fields.forEach(field => {
                const row = document.createElement('div');
                row.className = 'field-row';

                label.textContent = field + ':';

                let input;
                
                // SOME/IP-SD payload 显示为居中标签
                if (protocol === 'SOMEIP-SD' && field === 'payload') {
                    const labelDiv = document.createElement('div');
                    labelDiv.style.cssText = 'text-align: center; color: #666; font-style: italic; padding: 5px; background: #f5f5f5; border-radius: 3px; flex: 1;';
                    labelDiv.textContent = '-payload-sd-';
                    labelDiv.id = type === 'legal' ? `legal-${protocol}-${field}` : `illegal-${protocol}-${field}`;
                    labelDiv.dataset.protocol = protocol;
                    labelDiv.dataset.field = field;
                    row.appendChild(label);
                    row.appendChild(labelDiv);
                    group.appendChild(row);
                    return;
                }
                
                // SOME/IP-SD 固定值字段置灰显示
                if (protocol === 'SOMEIP-SD' && someipSdFixedFields.includes(field)) {
                    input = document.createElement('input');
                    input.type = 'text';
                    input.dataset.protocol = protocol;
                    input.dataset.field = field;
                    input.readOnly = true;
                    input.style.cssText = 'background: #f0f0f0; color: #999; cursor: not-allowed;';
                    
                    // Bug Fix 4: 使用从API获取的默认值
                    let defaultValue;
                    if (type === 'legal') {
                        defaultValue = getLegalDefault(protocol, field);
                        input.id = `legal-${protocol}-${field}`;
                    } else {
                        defaultValue = getIllegalDefault(protocol, field);
                        input.id = `illegal-${protocol}-${field}`;
                    }
                    input.value = defaultValue;
                }
                // SOME/IP-SD option_type 使用下拉框
                else if (protocol === 'SOMEIP-SD' && field === 'option_type') {
                    input = document.createElement('select');
                    input.dataset.protocol = protocol;
                    input.dataset.field = field;
                    
                    const options = [
                        { value: '0x04', text: '0x04 (IPv4 Endpoint)' },
                        { value: '0x06', text: '0x06 (IPv6 Endpoint)' },
                        { value: '0x14', text: '0x14 (IPv4 Multicast)' },
                        { value: '0x16', text: '0x16 (IPv6 Multicast)' },
                        { value: '0x01', text: '0x01 (Configuration)' },
                        { value: '0x02', text: '0x02 (Load Balancing)' },
                        { value: '0x24', text: '0x24 (IPv4 SD Endpoint)' },
                        { value: '0x26', text: '0x26 (IPv6 SD Endpoint)' }
                    ];
                    
                    options.forEach(opt => {
                        const option = document.createElement('option');
                        option.value = opt.value;
                        option.textContent = opt.text;
                        input.appendChild(option);
                    });
                    
                    // Bug Fix 4: 使用从API获取的默认值
                    let defaultValue;
                    if (type === 'legal') {
                        defaultValue = getLegalDefault(protocol, field);
                        input.id = `legal-${protocol}-${field}`;
                    } else {
                        defaultValue = getIllegalDefault(protocol, field);
                        input.id = `illegal-${protocol}-${field}`;
                    }
                    input.value = defaultValue;
                } else {
                    input = document.createElement('input');
                    input.type = 'text';
                    input.dataset.protocol = protocol;
                    input.dataset.field = field;

                    // Bug Fix 4: 使用从API获取的默认值
                    let defaultValue;
                    if (type === 'legal') {
                        defaultValue = getLegalDefault(protocol, field);
                        input.id = `legal-${protocol}-${field}`;
                    } else {
                        defaultValue = getIllegalDefault(protocol, field);
                        input.id = `illegal-${protocol}-${field}`;
                    }
                    input.value = defaultValue;
                }

                row.appendChild(label);
                row.appendChild(input);
                group.appendChild(row);
            });

            return group;
        }

        // 绑定事件
        function toggleField(field) {
            legalSendMode = false;
            updateLegalSendBtn();
            fieldStates[field] = !fieldStates[field];
            updateFieldButtons();
            
            // Populate the corresponding input with the illegal value
            if (fieldStates[field]) {
                populateFieldWithIllegalValue(field);
            } else {
                populateFieldWithLegalValue(field);
            }
        }

        // Populate field input with illegal value
        function populateFieldWithIllegalValue(field) {
            // Find which protocol this field belongs to
            for (const protocol of Object.keys(protocolFields)) {
                if (protocolFields[protocol].includes(field)) {
                    const illegalValue = illegalDefaults[protocol]?.[field] || 'INVALID';
                    // Try to find and update the input in the illegal values section
                    const illegalInput = document.getElementById(`illegal-${protocol}-${field}`);
                    if (illegalInput) {
                        // Copy the illegal value to the illegal input (or we could show a tooltip)
                        addLog(`[字段] ${field} 使用非法值: ${illegalValue}`);
                    }
                    break;
                }
            }
        }

        // Populate field input with legal value
        function populateFieldWithLegalValue(field) {
            for (const protocol of Object.keys(protocolFields)) {
                if (protocolFields[protocol].includes(field)) {
                    const legalValue = legalDefaults[protocol]?.[field] || '0';
                    addLog(`[字段] ${field} 恢复合法值: ${legalValue}`);
                    break;
                }
            }
        }

        // 更新合法发送按钮
        function updateLegalSendBtn() {
            btn.classList.toggle('inactive', !legalSendMode);
        }

        // 更新字段按钮样式
        function updateFieldButtons() {
            const buttons = document.querySelectorAll('.field-btn');
            buttons.forEach(btn => {
                const field = btn.textContent;
                btn.classList.toggle('illegal', fieldStates[field]);
            });
        }

        // 获取字段值
        function getFieldValue(protocol, field, useLegal) {
            const inputId = useLegal ?
                `legal-${protocol}-${field}` :
                `illegal-${protocol}-${field}`;
            const input = document.getElementById(inputId);
            return input ? input.value : '';
        }

        // 组装报文
        function buildPacketData(protocol, illegalFields) {
            const data = {};

            fields.forEach(field => {
                const useLegal = !illegalFields.includes(field);
                data[field] = getFieldValue(protocol, field, useLegal);
            });

            return data;
        }

        // Build packet hex string for scapy send
        function buildPacketHex(protocol, packetData) {
            if (protocol === 'ARP') {
                // ARP packet: hwtype(2) + proto(2) + hwlen(1) + protolen(1) + opcode(2) + srcmac(6) + srcip(4) + dstmac(6) + dstip(4)
                const hwtype = '0001';
                const proto = packetData['proto.type'] ? packetData['proto.type'].replace('0x', '').substring(0, 4) : '0800';
                const hwlen = '06';
                const protolen = '04';
                const opcode = packetData['opcode'] ? packetData['opcode'].replace('0x', '').substring(0, 4) : '0001';
                const srcmac = packetData['src.hw_mac'] ? packetData['src.hw_mac'].replace(/[:-]/g, '').substring(0, 12) : '001122334455';
                const dstmac = packetData['dst.hw_mac'] ? packetData['dst.hw_mac'].replace(/[:-]/g, '').substring(0, 12) : '000000000000';
                
                // Convert IP to hex (simplified - using dummy values if not provided)
                const srcip = 'c0a80164'; // 192.168.1.100
                const dstip = 'c0a80101'; // 192.168.1.1
                
                return hwtype + proto + hwlen + protolen + opcode + srcmac + srcip + dstmac + dstip;
            }
            return '';
        }

        // 添加日志
        function highlightHexByField(fieldId) {
            console.log('[DEBUG] highlightHexByField called, fieldId:', fieldId);
            const pkt = currentSelectedPacket;
            if (!pkt || !pkt.raw_bytes) {
                console.log('[DEBUG] No packet or raw_bytes');
                return;
            }
            
            // 分层查找字段定义
            const layers = ['ETHERNET', 'ARP', 'IP', 'TCP', 'UDP', 'ICMP', 'SOMEIP', 'SOMEIP-SD', 'DOIP'];
            let foundLayer = null;
            
            for (const layer of layers) {
                const offsets = fieldBitOffsets[layer];
                if (offsets && offsets[fieldId]) {
                    field = offsets[fieldId];
                    foundLayer = layer;
                    break;
                }
            }
            
            if (!field) {
                console.log('[DEBUG] Field not found:', fieldId);
                return;
            }
            
            console.log('[DEBUG] Found in layer:', foundLayer, 'Field:', field);
            
            const startByte = field.offset;
            const endByte = field.offset + (field.length || 1);
            
            console.log('[DEBUG] Highlighting bytes from', startByte, 'to', endByte);
            
            // 高亮Hex字节
            const hexBytes = document.querySelectorAll('.hex-byte');
            console.log('[DEBUG] Total hex bytes:', hexBytes.length);
            
            hexBytes.forEach((el, index) => {
                el.classList.remove('selected');
                if (index >= startByte && index < endByte) {
                    el.classList.add('selected');
                }
            });
            
            // 滚动到对应位置
            if (hexBytes[startByte]) {
                hexBytes[startByte].scrollIntoView({ behavior: 'smooth', block: 'center' });
            }
        }

        // 根据偏移量高亮 Hex 字节（用于 Options 子项等动态字段）
        function highlightHexByOffset(startByte, length) {
            console.log('[DEBUG] highlightHexByOffset called, start:', startByte, 'length:', length);
            
            // 高亮Hex字节
            
            hexBytes.forEach((el, index) => {
                el.classList.remove('selected');
                if (index >= startByte && index < endByte) {
                    el.classList.add('selected');
                }
            });
            
            // 滚动到对应位置
            if (hexBytes[startByte]) {
                hexBytes[startByte].scrollIntoView({ behavior: 'smooth', block: 'center' });
            }
        }

        // 双向映射核心函数：Hex → 协议层级
        function highlightFieldByHexByte(byteOffset) {
            console.log('[DEBUG] highlightFieldByHexByte called, offset:', byteOffset);
            
            // 在所有协议层中查找包含该字节的字段
            let bestMatch = null;
            let smallestRange = Infinity;
            
            for (const layer of layers) {
                if (!offsets) continue;
                
                for (const [fieldId, field] of Object.entries(offsets)) {
                    const start = field.offset;
                    const end = field.offset + (field.length || 1);
                    
                    if (byteOffset >= start && byteOffset < end) {
                        const range = end - start;
                        if (range < smallestRange) {
                            smallestRange = range;
                            bestMatch = fieldId;
                        }
                    }
                }
            }
            
            console.log('[DEBUG] Best match:', bestMatch);
            
            // 先尝试匹配预定义字段
            if (bestMatch) {
                // 高亮协议树中的字段
                document.querySelectorAll('.packet-tree-item').forEach(el => {
                    el.classList.remove('selected');
                    if (el.dataset.fieldId === bestMatch) {
                        el.classList.add('selected');
                        el.scrollIntoView({ behavior: 'smooth', block: 'center' });
                    }
                });
                selectedFieldId = bestMatch;
            }
            
            // 然后尝试匹配 Options 子项（基于 data-offset）
            const treePanel = document.getElementById('packetTreePanel');
            if (treePanel) {
                const optionItems = treePanel.querySelectorAll('.packet-tree-item[data-offset]');
                optionItems.forEach(el => {
                    const optOffset = parseInt(el.dataset.offset);
                    const optLength = parseInt(el.dataset.length || 1);
                    if (byteOffset >= optOffset && byteOffset < optOffset + optLength) {
                        el.classList.add('selected');
                        el.scrollIntoView({ behavior: 'smooth', block: 'center' });
                        selectedFieldId = el.dataset.fieldId;
                    }
                });
            }
        }

        // 检查字段是否为非法值
        function isIllegalField(protocol, fieldId, value) {
            if (!illegalDefaults[protocol]) return false;
            if (!illegalValue) return false;
            
            // 简化比较 - 检查是否匹配非法值
            return value && value.toString().toLowerCase().includes(illegalValue.toLowerCase());
        }

        // 切换详情标签
