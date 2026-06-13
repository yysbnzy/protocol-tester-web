function buildPacketData(protocol, illegalFields) {
    const data = {};
    const fields = protocolFields[protocol] || [];
    
    fields.forEach(field => {
        const fieldShort = field.replace(`${protocol}.`, '').replace(`${protocol}-`, '');
        const isIllegal = illegalFields.includes(field);
        const inputId = isIllegal ? `illegal-${protocol}-${fieldShort}` : `legal-${protocol}-${fieldShort}`;
        const input = document.getElementById(inputId);
        if (input) {
            data[fieldShort] = input.value;
        }
    });
    
    // ARP协议：自动注入当前网卡的IP和MAC作为源地址，固定协议类型
    if (protocol === 'ARP') {
        const nicSelect = document.getElementById('nicSelect');
        if (nicSelect && nicSelect.value) {
            const selectedNic = allNics.find(n => n.name === nicSelect.value);
            if (selectedNic) {
                // 仅在用户未指定或仍为默认值时注入网卡地址
                if (!data['src_ip'] || data['src_ip'] === '192.168.1.100') {
                    data['src_ip'] = selectedNic.ip;
                }
                if (!data['src.hw_mac'] || data['src.hw_mac'] === '00:11:22:33:44:55') {
                    data['src.hw_mac'] = selectedNic.mac;
                }
            }
        }
        // 固定ARP协议类型为IPv4
        data['proto.type'] = '0x0800';
        // ARP目标MAC：空时自动设为广播地址
        if (!data['dst.hw_mac'] || data['dst.hw_mac'] === '00:00:00:00:00:00') {
            data['dst.hw_mac'] = 'ff:ff:ff:ff:ff:ff';
        }
    }
    
    // IP/ICMP协议：自动注入源IP
    if (protocol === 'IP' || protocol === 'ICMP') {
        const nicSelect = document.getElementById('nicSelect');
        if (nicSelect && nicSelect.value) {
            const selectedNic = allNics.find(n => n.name === nicSelect.value);
            if (selectedNic && (!data['src'] || data['src'] === '192.168.1.100')) {
                data['src'] = selectedNic.ip;
            }
        }
    }
    
    // TCP/UDP/ICMP协议：自动注入IP层字段（从目标IP输入框和网卡获取）
    if (protocol === 'TCP' || protocol === 'UDP' || protocol === 'ICMP') {
        const targetIp = document.getElementById('targetIp').value || '192.168.1.1';
        const nicSelect = document.getElementById('nicSelect');
        let srcIp = '192.168.1.100';
        if (nicSelect && nicSelect.value) {
            const selectedNic = allNics.find(n => n.name === nicSelect.value);
            if (selectedNic) {
                srcIp = selectedNic.ip;
            }
        }
        // 添加IP层字段（如果用户未指定）
        if (!data['src'] && !data['IP.src']) {
            data['src'] = srcIp;
        }
        if (!data['dst'] && !data['IP.dst']) {
            data['dst'] = targetIp;
        }
    }
    
    return data;
}

function buildPacketHex(protocol, packetData) {
    // 简易实现:将协议和字段数据序列化为十六进制字符串
    // 实际应由后端 /api/scapy/build 接口处理
    return JSON.stringify({protocol, fields: packetData});
}
