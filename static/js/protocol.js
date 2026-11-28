const PAYLOAD_FIELD = 'Payload.payload';

// 独立 Payload 只归属于当前协议栈的最内层，避免在多层报文中重复拼接。
function getPayloadProtocol() {
    if (selectedProtocols.includes('SOMEIP-SD')) return null;
    return ['TLS', 'DOIP', 'SOMEIP', 'TCP', 'UDP', 'ICMP', 'IP']
        .find(protocol => selectedProtocols.includes(protocol)) || null;
}

// 仅缩短界面显示名称，内部字段键和组包协议名仍使用 SOMEIP-SD。
function getFieldDisplayName(field) {
    return field.startsWith('SOMEIP-SD.') ? `SD.${field.slice('SOMEIP-SD.'.length)}` : field;
}

function renderFieldButtons() {
            const container = document.getElementById('fieldButtons');
            container.innerHTML = '';
            // Bug Fix 2: 不要在这里清空fieldStates，保留用户选择的字段状态
            // 但如果协议被取消选择，应该清除该协议的字段状态
            
            console.log('[DEBUG] Rendering fields for', selectedProtocols);
            
            if (selectedProtocols.length === 0) {
                container.innerHTML = '<div style="padding:10px;color:var(--muted-foreground);">Select at least one protocol</div>';
                return;
            }
            
            // Bug Fix 2: 清理不再选中的协议的字段状态
            Object.keys(fieldStates).forEach(field => {
                if (field === PAYLOAD_FIELD && getPayloadProtocol()) return;
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
            const protocolOrder = ['ARP', 'IP', 'ICMP', 'TCP', 'UDP', 'SOMEIP', 'SOMEIP-SD', 'DOIP', 'TLS'];
            
            // Display fields in fixed protocol order
            protocolOrder.forEach(protocol => {
                if (protocol !== 'Payload' && selectedProtocols.includes(protocol)) {
                    const fields = protocolFields[protocol] || [];
                    if (fields.length > 0) {
                        // Protocol label
                        const label = document.createElement('div');
                        // SOMEIP-SD 使用更小的字体
                        const fontSize = protocol === 'SOMEIP-SD' ? '9px' : '10px';
                        label.style.cssText = `font-size:${fontSize};color:var(--primary);padding:2px 0;margin:5px 0;text-align:center;`;
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
                            const fieldShort = field.startsWith(`${protocol}.`) ? field.slice(protocol.length + 1) : field;
                            btn.dataset.testid = 'field-btn-' + protocol + '-' + fieldShort;
                            btn.dataset.field = field;
                            btn.textContent = getFieldDisplayName(field);
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

            if (getPayloadProtocol()) {
                const label = document.createElement('div');
                label.style.cssText = 'font-size:10px;color:var(--primary);padding:2px 0;margin:5px 0;text-align:center;';
                label.textContent = '—Payload—';
                container.appendChild(label);

                if (!(PAYLOAD_FIELD in fieldStates)) fieldStates[PAYLOAD_FIELD] = false;
                const button = document.createElement('button');
                button.className = 'field-btn';
                button.dataset.testid = 'field-btn-Payload-payload';
                button.dataset.field = PAYLOAD_FIELD;
                button.textContent = 'Payload';
                button.onclick = () => toggleField(PAYLOAD_FIELD);
                container.appendChild(button);
            }
            
            // Update values display - Bug Fix 2: 强制更新显示
            updateValuesDisplay();
        }

function updateValuesDisplay() {
            // Show values for all selected protocols
            document.querySelectorAll('.protocol-group').forEach(group => {
                const title = group.querySelector('h4');
                if (title) {
                    const protocol = group.dataset.protocol || title.textContent.replace('-', '');
                    const visible = protocol === 'Payload'
                        ? Boolean(getPayloadProtocol()) : selectedProtocols.includes(protocol);
                    group.style.display = visible ? 'block' : 'none';
                }
            });
        }

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
            group.dataset.protocol = protocol;

            const titleRow = document.createElement('div');
            titleRow.className = 'protocol-title-row';

            const title = document.createElement('h4');
            title.textContent = protocol === 'Payload' ? '—Payload—' : `-${protocol}`;
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

            const fields = protocolFields[protocol] || [];
            
            // SOME/IP-SD 固定值字段（不可编辑）
            const someipSdFixedFields = ['service_id', 'method_id', 'client_id', 'proto_ver', 'iface_ver', 'msg_type', 'retcode'];
            
            fields.forEach(field => {
                const row = document.createElement('div');
                row.className = 'field-row';
                if (field === PAYLOAD_FIELD) row.classList.add('payload-field-row');

                const label = document.createElement('label');
                label.textContent = getFieldDisplayName(field) + ':';

                let input;
                // 生成短字段名（去掉协议前缀，如 TCP.srcport -> srcport）
                const fieldShort = field.startsWith(`${protocol}.`) ? field.slice(protocol.length + 1) : field;
                
                // SOME/IP-SD payload 显示为居中标签
                if (protocol === 'SOMEIP-SD' && field === 'payload') {
                    const labelDiv = document.createElement('div');
                    labelDiv.style.cssText = 'text-align: center; color: var(--muted-foreground); font-style: italic; padding: 5px; background: var(--secondary); border-radius: 3px; flex: 1;';
                    labelDiv.textContent = '-payload-sd-';
                    labelDiv.id = type === 'legal' ? `legal-${protocol}-${fieldShort}` : `illegal-${protocol}-${fieldShort}`;
                    labelDiv.dataset.protocol = protocol;
                    labelDiv.dataset.field = fieldShort;
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
                    input.dataset.field = fieldShort;
                    input.readOnly = true;
                    input.style.cssText = 'background: var(--secondary); color: var(--muted-foreground); cursor: not-allowed;';
                    
                    // Bug Fix 4: 使用从API获取的默认值
                    let defaultValue;
                    if (type === 'legal') {
                        defaultValue = getLegalDefault(protocol, field);
                        input.id = `legal-${protocol}-${fieldShort}`;
                    } else {
                        defaultValue = getIllegalDefault(protocol, field);
                        input.id = `illegal-${protocol}-${fieldShort}`;
                    }
                    input.value = defaultValue;
                }
                // SOME/IP-SD option_type 使用下拉框
                else if (protocol === 'SOMEIP-SD' && field === 'option_type') {
                    input = document.createElement('select');
                    input.dataset.protocol = protocol;
                    input.dataset.field = fieldShort;
                    
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
                        input.id = `legal-${protocol}-${fieldShort}`;
                    } else {
                        defaultValue = getIllegalDefault(protocol, field);
                        input.id = `illegal-${protocol}-${fieldShort}`;
                    }
                    input.value = defaultValue;
                } else {
                    input = document.createElement(field === PAYLOAD_FIELD ? 'textarea' : 'input');
                    if (field !== PAYLOAD_FIELD) input.type = 'text';
                    input.dataset.protocol = protocol;
                    input.dataset.field = fieldShort;

                    // Bug Fix 4: 使用从API获取的默认值
                    let defaultValue;
                    if (type === 'legal') {
                        defaultValue = getLegalDefault(protocol, field);
                        input.id = `legal-${protocol}-${fieldShort}`;
                    } else {
                        defaultValue = getIllegalDefault(protocol, field);
                        input.id = `illegal-${protocol}-${fieldShort}`;
                    }
                    input.value = defaultValue;
                }

                input.dataset.testid = `input-${type}-${protocol}-${fieldShort}`;
                if (fieldShort === 'payload') {
                    input.placeholder = 'HEX / hex:... / ascii:...';
                    input.title = '支持 HEX、hex: 和 ascii: 前缀；非法模式下的非 HEX 文本按 UTF-8 字节发送';
                }
                if (field === PAYLOAD_FIELD) input.wrap = 'soft';
                if (['length', 'payload_len', 'total_len'].includes(fieldShort)) {
                    input.title = '合法发送时自动按真实报文计算；选中为非法字段后使用填写的值';
                    if (type === 'legal') {
                        input.readOnly = true;
                        input.style.background = 'var(--secondary)';
                    }
                }
                if (field !== PAYLOAD_FIELD) row.appendChild(label);
                row.appendChild(input);
                group.appendChild(row);
            });

            return group;
        }

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
                if (protocol === 'TLS') {
                    selectedProtocols = selectedProtocols.filter(p => p !== 'ARP');
                }
                
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
                
                // 规则7: TLS 只使用 TCP；Record 组包不代表完成 TLS 加密握手。
                if (protocol === 'TLS') {
                    const udpIndex = selectedProtocols.indexOf('UDP');
                    if (udpIndex > -1) selectedProtocols.splice(udpIndex, 1);
                    if (!selectedProtocols.includes('TCP')) selectedProtocols.push('TCP');
                    const tcpPortInput = document.getElementById('legal-TCP-dstport');
                    if (tcpPortInput && tcpPortInput.value === '80') tcpPortInput.value = '443';
                    const targetPortInput = document.getElementById('targetPort');
                    if (targetPortInput && targetPortInput.value === '80') targetPortInput.value = '443';
                    showToast('TLS 使用 TCP，已自动选择 TCP；Socket 执行真实 TLS 握手，Raw/Npcap 仅组包', 3500);
                }

                // 规则8: SOMEIP/DOIP 提示需要传输层
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

function populateFieldWithIllegalValue(field) {
            // Find which protocol this field belongs to
            for (const protocol of Object.keys(protocolFields)) {
                if (protocolFields[protocol].includes(field)) {
                    const illegalValue = getIllegalDefault(protocol, field);
                    const fieldShort = field.startsWith(`${protocol}.`) ? field.slice(protocol.length + 1) : field;
                    // Try to find and update the input in the illegal values section
                    const illegalInput = document.getElementById(`illegal-${protocol}-${fieldShort}`);
                    if (illegalInput) {
                        illegalInput.value = illegalValue;
                        addLog(`[字段] ${field} 使用非法值: ${illegalValue}`);
                    }
                    break;
                }
            }
        }

function populateFieldWithLegalValue(field) {
            for (const protocol of Object.keys(protocolFields)) {
                if (protocolFields[protocol].includes(field)) {
                    const legalValue = getLegalDefault(protocol, field);
                    const fieldShort = field.startsWith(`${protocol}.`) ? field.slice(protocol.length + 1) : field;
                    const legalInput = document.getElementById(`legal-${protocol}-${fieldShort}`);
                    if (legalInput) {
                        legalInput.value = legalValue;
                        addLog(`[字段] ${field} 恢复合法值: ${legalValue}`);
                    }
                    break;
                }
            }
        }

function updateLegalSendBtn() {
            const btn = document.getElementById('legalSendBtn');
            btn.classList.toggle('inactive', !legalSendMode);
        }

function updateFieldButtons() {
            const buttons = document.querySelectorAll('.field-btn');
            buttons.forEach(btn => {
                const field = btn.dataset.field || btn.textContent;
                btn.classList.toggle('illegal', fieldStates[field]);
            });
        }

