from backend.core.scapy_sender import ScapyRawSender

sender = ScapyRawSender()

# Test IP + SOMEIP without UDP
result = sender.build_multi_protocol_packet(
    ['IP', 'SOMEIP'],
    {
        'IP': {'src': '192.168.1.100', 'dst': '192.168.1.1'},
        'SOMEIP': {'service': '0x1234', 'method': '0x5678'}
    }
)
if result['success']:
    from scapy.all import IP as ScapyIP
    pkt = ScapyIP(bytes(result['packet_bytes']))
    print(f'IP+SOMEIP: proto={pkt.proto} (expected=17 for UDP)')

# Test IP + DOIP without TCP
result = sender.build_multi_protocol_packet(
    ['IP', 'DOIP'],
    {
        'IP': {'src': '192.168.1.100', 'dst': '192.168.1.1'},
        'DOIP': {'version': '0x02', 'payload_type': '0x0001'}
    }
)
if result['success']:
    pkt = ScapyIP(bytes(result['packet_bytes']))
    print(f'IP+DOIP: proto={pkt.proto} (expected=6 for TCP)')

# Test TCP with options
result = sender.build_multi_protocol_packet(
    ['IP', 'TCP'],
    {
        'IP': {'src': '192.168.1.100', 'dst': '192.168.1.1'},
        'TCP': {'srcport': '12345', 'dstport': '80', 'flags': 'S', 'options': '0x020405b4'}
    }
)
if result['success']:
    print(f'IP+TCP with options: {len(result["packet_bytes"])} bytes')
    from scapy.all import TCP as ScapyTCP
    pkt = ScapyTCP(bytes(result['packet_bytes'])[20:])
    print(f'  TCP options: {pkt.options}')
