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
    
    return data;
}

function buildPacketHex(protocol, packetData) {
    // 简易实现:将协议和字段数据序列化为十六进制字符串
    // 实际应由后端 /api/scapy/build 接口处理
    return JSON.stringify({protocol, fields: packetData});
}
