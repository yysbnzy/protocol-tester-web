# -*- coding: utf-8 -*-
"""Payload 真实拼接、长度联动与 PCAP 编辑闭环测试。"""

import io
import json
import os
import sys
import tempfile

import pytest
from scapy.all import Ether, IP, Raw, TCP, UDP, rdpcap, wrpcap

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, init_app, limiter
from backend.core.packet_assembler import PacketAssembler
from backend.core.scapy_sender import ScapyRawSender

init_app()


@pytest.fixture
def client():
    app.config['TESTING'] = True
    limiter.enabled = False
    with app.test_client() as test_client:
        yield test_client


@pytest.fixture
def sender():
    return ScapyRawSender()


def test_doip_payload_and_length_are_real(sender):
    result = sender.build_multi_protocol_packet(
        ['IP', 'TCP', 'DOIP'],
        {'IP': {}, 'TCP': {'dstport': '13400'},
         'DOIP': {'version': '2', 'inv_version': '0xFD',
                  'payload_type': '0x8001', 'payload': '0E 80 10 01 22 33'}},
    )
    assert result['success']
    packet = bytes(result['packet_bytes'])
    assert packet.endswith(bytes.fromhex('02fd8001000000060e8010012233'))
    assert packet[2:4] == (54).to_bytes(2, 'big')


def test_doip_illegal_length_is_not_auto_corrected(sender):
    result = sender.build_multi_protocol_packet(
        ['DOIP'], {'DOIP': {'payload': '01020304', 'payload_len': '1'}},
        {'DOIP': ['DOIP.payload_len']},
    )
    packet = bytes(result['packet_bytes'])
    assert packet[-8:-4] == bytes.fromhex('00000001')
    assert packet[-4:] == bytes.fromhex('01020304')


def test_someip_length_includes_fixed_eight_bytes(sender):
    result = sender.build_multi_protocol_packet(
        ['IP', 'UDP', 'SOMEIP'], {'SOMEIP': {'payload': 'DEADBEEF'}},
    )
    packet = bytes(result['packet_bytes'])
    someip = packet[28:]
    assert someip[4:8] == (12).to_bytes(4, 'big')
    assert someip[-4:] == bytes.fromhex('DEADBEEF')


@pytest.mark.parametrize('protocol', ['IP', 'TCP', 'UDP', 'ICMP'])
def test_generic_payload_is_appended(sender, protocol):
    result = sender.build_multi_protocol_packet(
        [protocol], {protocol: {'payload': 'ascii:ABC'}},
    )
    assert result['success']
    assert bytes(result['packet_bytes']).endswith(b'ABC')


def test_udp_illegal_length_is_preserved(sender):
    result = sender.build_multi_protocol_packet(
        ['UDP'], {'UDP': {'payload': '0102', 'length': '3'}},
        {'UDP': ['UDP.length']},
    )
    packet = bytes(result['packet_bytes'])
    assert packet[24:26] == b'\x00\x03'
    assert packet[-2:] == b'\x01\x02'


def test_legacy_assembler_matches_doip_payload():
    result = PacketAssembler().assemble('DOIP', {'payload': '0E801001'})
    packet = bytes(result['packet_bytes'])
    assert packet[4:8] == (4).to_bytes(4, 'big')
    assert packet[-4:] == bytes.fromhex('0E801001')


def test_pcap_import_backfills_doip_fields(client):
    doip = bytes.fromhex('02fd8001000000060e8010012233')
    source = Ether() / IP(src='192.168.2.100', dst='192.168.2.24') / TCP(sport=40000, dport=13400) / Raw(doip)
    with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as temp:
        path = temp.name
    try:
        wrpcap(path, [source])
        with open(path, 'rb') as stream:
            response = client.post('/api/pcap/import', data={
                'file': (io.BytesIO(stream.read()), 'doip.pcap'),
            }, content_type='multipart/form-data')
        assert response.status_code == 200
        result = response.get_json()
        assert result['success'] and result['packet_count'] == 1
        packet = result['packets'][0]
        assert packet['protocols'] == ['IP', 'TCP', 'DOIP']
        assert packet['fields']['DOIP']['payload'] == '0e8010012233'
        assert packet['fields']['DOIP']['payload_len'] == '6'
        assert packet['fields']['IP']['dst'] == '192.168.2.24'
    finally:
        os.remove(path)


def test_pcap_import_rejects_wrong_extension(client):
    response = client.post('/api/pcap/import', data={
        'file': (io.BytesIO(b'not a capture'), 'bad.txt'),
    }, content_type='multipart/form-data')
    assert response.status_code == 400


def test_current_packet_can_export_and_download(client):
    packet = Ether() / IP() / UDP() / Raw(b'ABC')
    response = client.post('/api/pcap/export', json={
        'packets': [bytes(packet).hex()], 'filename': 'edited-test.pcap',
    })
    result = response.get_json()
    assert result['success'] and result['packet_count'] == 1
    download = client.get('/api/pcap/download/edited-test.pcap')
    assert download.status_code == 200
    with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as temp:
        temp.write(download.data)
        path = temp.name
    try:
        exported = rdpcap(path)
        assert len(exported) == 1
        assert bytes(exported[0]).endswith(b'ABC')
    finally:
        os.remove(path)


def test_existing_ethernet_frame_is_not_encapsulated_again(sender):
    from unittest.mock import patch
    frame = Ether(src='02:00:00:00:00:01', dst='02:00:00:00:00:02') / IP() / UDP()
    with patch('scapy.all.sendp') as sendp:
        result = sender.send_raw_packet(bytes(frame), count=1)
    assert result['success']
    sent = sendp.call_args.args[0]
    assert bytes(sent) == bytes(frame)
