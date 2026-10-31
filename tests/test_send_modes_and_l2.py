# -*- coding: utf-8 -*-
"""发送模式与 raw 二层目的 MAC 解析测试"""

import json
import os
import sys
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, limiter, init_app
from backend.core.scapy_sender import ScapyRawSender

init_app()


@pytest.fixture
def client():
    app.config['TESTING'] = True
    limiter.enabled = False
    with app.test_client() as test_client:
        yield test_client


def ipv4_packet(dst=(192, 168, 1, 20)):
    packet = bytearray(20)
    packet[0] = 0x45
    packet[12:16] = bytes([192, 168, 1, 100])
    packet[16:20] = bytes(dst)
    return bytes(packet)


class TestSendModeApi:
    def test_simulate_never_calls_raw_sender(self, client):
        with patch('backend.core.scapy_sender.ScapyRawSender.send_raw_packet') as send:
            resp = client.post('/api/scapy/send',
                data=json.dumps({
                    'packet_hex': ipv4_packet().hex(),
                    'mode': 'simulate',
                    'count': 100
                }),
                content_type='application/json')
            assert resp.status_code == 200
            data = resp.get_json()
            assert data['success'] is True
            assert data['sent'] == 0
            assert data['mode'] == 'simulate'
            send.assert_not_called()

    def test_socket_is_rejected_instead_of_silent_raw(self, client):
        with patch('backend.core.scapy_sender.ScapyRawSender.send_raw_packet') as send:
            resp = client.post('/api/scapy/send',
                data=json.dumps({'packet_hex': ipv4_packet().hex(), 'mode': 'socket'}),
                content_type='application/json')
            assert resp.status_code == 400
            assert resp.get_json()['success'] is False
            send.assert_not_called()

    @pytest.mark.parametrize('mode', ['raw', 'npcap'])
    def test_raw_modes_reach_raw_sender(self, client, mode):
        with patch('backend.core.scapy_sender.ScapyRawSender.send_raw_packet',
                   return_value={'success': True, 'message': 'ok'}) as send:
            resp = client.post('/api/scapy/send',
                data=json.dumps({'packet_hex': ipv4_packet().hex(), 'mode': mode}),
                content_type='application/json')
            assert resp.status_code == 200
            assert resp.get_json()['mode'] == mode
            send.assert_called_once()


class TestRawIPv4DestinationMac:
    def test_same_subnet_uses_target_mac(self):
        sender = ScapyRawSender()
        with patch('backend.core.scapy_sender.conf.route.route',
                   return_value=('eth0', '192.168.1.100', '0.0.0.0')), \
             patch('backend.core.scapy_sender.getmacbyip', return_value='aa:bb:cc:dd:ee:ff') as lookup:
            mac, _ = sender._resolve_ipv4_dst_mac(ipv4_packet(), 'eth0')
            assert mac == 'aa:bb:cc:dd:ee:ff'
            lookup.assert_called_once_with('192.168.1.20')

    def test_cross_subnet_uses_gateway_mac(self):
        sender = ScapyRawSender()
        packet = ipv4_packet((10, 0, 0, 8))
        with patch('backend.core.scapy_sender.conf.route.route',
                   return_value=('eth0', '192.168.1.100', '192.168.1.1')), \
             patch('backend.core.scapy_sender.getmacbyip', return_value='11:22:33:44:55:66') as lookup:
            mac, _ = sender._resolve_ipv4_dst_mac(packet, 'eth0')
            assert mac == '11:22:33:44:55:66'
            lookup.assert_called_once_with('192.168.1.1')

    def test_unresolved_mac_fails_instead_of_broadcast(self):
        sender = ScapyRawSender()
        with patch('backend.core.scapy_sender.conf.route.route',
                   return_value=('eth0', '192.168.1.100', '0.0.0.0')), \
             patch('backend.core.scapy_sender.getmacbyip', return_value=None):
            with pytest.raises(ValueError, match='无法解析目标'):
                sender._resolve_ipv4_dst_mac(ipv4_packet(), 'eth0')

    def test_multicast_uses_standard_mapping_without_arp(self):
        sender = ScapyRawSender()
        packet = ipv4_packet((224, 244, 224, 245))
        with patch('backend.core.scapy_sender.getmacbyip') as lookup:
            mac, _ = sender._resolve_ipv4_dst_mac(packet)
            assert mac == '01:00:5e:74:e0:f5'
            lookup.assert_not_called()

    def test_manual_eth_dst_bypasses_resolution(self):
        sender = ScapyRawSender()
        with patch('backend.core.scapy_sender.get_if_hwaddr', return_value='00:11:22:33:44:55'), \
             patch('backend.core.scapy_sender.conf.route.route',
                   return_value=('eth0', '192.168.1.100', '0.0.0.0')), \
             patch.object(sender, '_resolve_ipv4_dst_mac') as resolve:
            ether, _ = sender._build_ether_header(
                ipv4_packet(), 'eth0', eth_dst='de:ad:be:ef:00:01'
            )
            assert ether.dst == 'de:ad:be:ef:00:01'
            resolve.assert_not_called()
