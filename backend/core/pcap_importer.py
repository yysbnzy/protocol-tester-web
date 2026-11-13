# -*- coding: utf-8 -*-
"""PCAP/PCAPNG 报文解析与字段回填。"""

from scapy.all import ARP, ICMP, IP, TCP, UDP, Ether, PcapReader, Raw


def _hex(value):
    return f'0x{value:X}'


def _application_fields(payload, protocols, fields):
    if len(payload) >= 8 and payload[0] == (payload[1] ^ 0xFF):
        protocols.append('DOIP')
        fields['DOIP'] = {
            'version': _hex(payload[0]),
            'inv_version': _hex(payload[1]),
            'payload_type': _hex(int.from_bytes(payload[2:4], 'big')),
            'payload_len': str(int.from_bytes(payload[4:8], 'big')),
            'payload': payload[8:].hex(),
        }
        return True
    if len(payload) < 16:
        return False
    service = int.from_bytes(payload[0:2], 'big')
    method = int.from_bytes(payload[2:4], 'big')
    msg_type = payload[14]
    is_someip = service == 0xFFFF and method == 0x8100
    if not is_someip and service == 0:
        return False
    protocol = 'SOMEIP-SD' if is_someip else 'SOMEIP'
    protocols.append(protocol)
    fields[protocol] = {
        'service': _hex(service), 'method': _hex(method),
        'length': str(int.from_bytes(payload[4:8], 'big')),
        'client': _hex(int.from_bytes(payload[8:10], 'big')),
        'session': _hex(int.from_bytes(payload[10:12], 'big')),
        'proto_ver': _hex(payload[12]), 'iface_ver': _hex(payload[13]),
        'msg_type': _hex(msg_type), 'retcode': _hex(payload[15]),
        'payload': payload[16:].hex(),
    }
    return True


def packet_to_editor(packet):
    protocols = []
    fields = {}
    summary = packet.summary()
    raw = bytes(packet)
    if ARP in packet:
        arp = packet[ARP]
        protocols = ['ARP']
        fields['ARP'] = {
            'opcode': _hex(arp.op), 'dst.hw_mac': arp.hwdst,
            'dst_ip': arp.pdst, 'src.hw_mac': arp.hwsrc, 'src_ip': arp.psrc,
            'proto.type': _hex(arp.ptype),
        }
    elif IP in packet:
        ip = packet[IP]
        protocols = ['IP']
        fields['IP'] = {
            'version': str(ip.version), 'tos': _hex(ip.tos),
            'total_len': str(ip.len), 'id': _hex(ip.id), 'ttl': str(ip.ttl),
            'checksum': _hex(ip.chksum or 0), 'src': ip.src, 'dst': ip.dst,
            'payload': '',
        }
        if TCP in packet or UDP in packet:
            transport = packet[TCP] if TCP in packet else packet[UDP]
            protocol = 'TCP' if TCP in packet else 'UDP'
            protocols.append(protocol)
            data = {
                'srcport': str(transport.sport), 'dstport': str(transport.dport),
                'checksum': _hex(transport.chksum or 0), 'payload': '',
            }
            if protocol == 'TCP':
                data.update({
                    'seq': str(transport.seq), 'ack': str(transport.ack),
                    'flags': _hex(int(transport.flags)),
                    'window_size': str(transport.window), 'options': '',
                })
            else:
                data['length'] = str(transport.len)
            fields[protocol] = data
            app_payload = bytes(transport.payload)
            if not _application_fields(app_payload, protocols, fields):
                fields[protocol]['payload'] = app_payload.hex()
        elif ICMP in packet:
            icmp = packet[ICMP]
            protocols.append('ICMP')
            fields['ICMP'] = {
                'type': str(icmp.type), 'code': str(icmp.code),
                'checksum': _hex(icmp.chksum or 0), 'id': _hex(icmp.id),
                'seq': str(icmp.seq), 'payload': bytes(icmp.payload).hex(),
            }
        else:
            fields['IP']['payload'] = bytes(ip.payload).hex()
    return {
        'summary': summary,
        'protocols': protocols,
        'fields': fields,
        'packet_hex': raw.hex(),
        'length': len(raw),
        'source': getattr(packet, 'src', ''),
        'destination': getattr(packet, 'dst', ''),
        'has_ethernet': Ether in packet,
    }


def read_pcap(path, max_packets=2000):
    packets = []
    with PcapReader(path) as reader:
        for index, packet in enumerate(reader):
            if index >= max_packets:
                break
            item = packet_to_editor(packet)
            item['index'] = index
            packets.append(item)
    return packets
