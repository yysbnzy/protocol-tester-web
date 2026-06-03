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
    
    // ARP协议：自动注入当前网卡的IP和MAC作为源地址
    if (protocol === 'ARP') {
        const nicSelect = document.getElementById('nicSelect');
        if (nicSelect && nicSelect.value) {
            const selectedNic = allNics.find(n => n.name === nicSelect.value);
            if (selectedNic) {
                if (!data['src_ip']) data['src_ip'] = selectedNic.ip;
                if (!data['src.hw_mac'] || data['src.hw_mac'] === '00:11:22:33:44:55') {
                    data['src.hw_mac'] = selectedNic.mac;
                }
            }
        }
        // ARP目标MAC：请求时为广播地址
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
    
    return data;
}

function buildPacketHex(protocol, packetData) {
    // 简易实现:将协议和字段数据序列化为十六进制字符串
    // 实际应由后端 /api/scapy/build 接口处理
    return JSON.stringify({protocol, fields: packetData});
}
