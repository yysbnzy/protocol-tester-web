# -*- coding: utf-8 -*-
"""发送模式与 raw 二层目的 MAC 解析测试"""

import json
import os
import sys
import struct
from datetime import datetime
from unittest.mock import Mock, patch

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


class TestPacketLayoutRegression:
    def test_someip_sd_standard_entry_and_ipv4_option_layout(self):
        from scapy.all import IP, UDP
        from backend.core.packet_assembler import PacketAssembler

        sender = ScapyRawSender()
        result = sender.build_multi_protocol_packet(
            ['IP', 'UDP', 'SOMEIP-SD'], {'SOMEIP-SD': {}}
        )
        assert result['success'] is True, result
        sd = bytes(IP(bytes.fromhex(result['packet_hex']))[UDP].payload)

        assert len(sd) == 56
        assert struct.unpack('>I', sd[4:8])[0] == 48
        assert sd[16] == 0xC0
        assert sd[17:20] == b'\x00' * 3
        assert struct.unpack('>I', sd[20:24])[0] == 16
        assert sd[24:28] == b'\x01\x00\x00\x10'
        assert sd[28:32] == b'\x12\x34\x00\x01'
        assert sd[32] == 1
        assert sd[33:36] == b'\x00\x00\x03'
        assert sd[36:40] == b'\x00' * 4
        assert struct.unpack('>I', sd[40:44])[0] == 12
        assert sd[44:48] == b'\x00\x09\x04\x00'
        assert sd[48:52] == bytes([192, 168, 1, 1])
        assert sd[52:56] == b'\x00\x06\x77\x2d'

        legacy = PacketAssembler().assemble('SOMEIP-SD', {})
        assert legacy['success'] is True, legacy
        assert bytes.fromhex(legacy['packet_hex']) == sd

    def test_tcp_options_follow_kind_and_length(self):
        from scapy.all import IP, TCP

        result = ScapyRawSender().build_multi_protocol_packet(
            ['IP', 'TCP'], {'TCP': {'options': '020405b401030307'}}
        )
        assert result['success'] is True, result
        options = IP(bytes.fromhex(result['packet_hex']))[TCP].options
        assert options == [('MSS', 1460), ('NOP', None), ('WScale', 7)]

    def test_invalid_tcp_options_are_not_silently_discarded(self):
        result = ScapyRawSender().build_multi_protocol_packet(
            ['IP', 'TCP'], {'TCP': {'options': 'INVALID_OPTIONS_DATA'}}
        )
        assert result['success'] is False
        assert 'Options' in result['error']

    @pytest.mark.parametrize('protocols', [
        ['IP', 'SOMEIP'],
        ['IP', 'SOMEIP-SD'],
        ['IP', 'DOIP'],
        ['ARP', 'IP'],
        ['IP', 'TCP', 'UDP'],
        ['IP', 'UDP', 'DOIP'],
        ['IP', 'TCP', 'SOMEIP-SD'],
    ])
    def test_invalid_protocol_stack_is_rejected(self, protocols):
        result = ScapyRawSender().build_multi_protocol_packet(protocols, {})
        assert result['success'] is False


class TestSendResultRegression:
    def test_established_socket_uses_sendall(self):
        from backend.core.tcp_manager import TCPConnectionManager, ConnectionState

        manager = TCPConnectionManager()
        sock = Mock()
        manager.connections['conn'] = {
            'socket': sock,
            'state': ConnectionState.ESTABLISHED,
            'mode': 'socket',
            'bytes_sent': 0,
            'packets_sent': 0,
            'error_count': 0,
            'last_activity': datetime.now(),
        }
        result = manager.send_malformed_packet('conn', b'12345678', is_binary=True)
        assert result['success'] is True
        assert result['bytes_sent'] == 8
        sock.sendall.assert_called_once_with(b'12345678')
        sock.send.assert_not_called()

    def test_batch_all_failures_return_failure(self):
        from backend.core.tcp_manager import TCPConnectionManager

        manager = TCPConnectionManager()
        with patch.object(manager, 'send_malformed_packet', return_value={
            'success': False, 'bytes_sent': 0, 'message': '模拟失败'
        }):
            result = manager.send_malformed_packet_batch('conn', b'x', 2, 0, True)
        assert result['success'] is False
        assert result['success_count'] == 0
        assert result['fail_count'] == 2
        assert result['total_sent'] == 0

    def test_udp_dict_payload_is_decoded(self):
        from backend.core.udp_icmp_sender import UDPSender

        sock = Mock()
        sock.sendto.return_value = 2
        with patch('backend.core.udp_icmp_sender.socket.socket', return_value=sock):
            result = UDPSender().send_packet(
                '127.0.0.1', 9, {'payload': '0102'}, 1, 0
            )
        assert result['success'] is True
        assert result['success_count'] == 1
        assert result['total_sent'] == 2
        sock.sendto.assert_called_once_with(b'\x01\x02', ('127.0.0.1', 9))

    def test_udp_all_failures_return_failure(self):
        from backend.core.udp_icmp_sender import UDPSender

        sock = Mock()
        sock.sendto.side_effect = OSError('模拟拒绝')
        with patch('backend.core.udp_icmp_sender.socket.socket', return_value=sock):
            result = UDPSender().send_packet(
                '127.0.0.1', 9, {'payload': '0102'}, 2, 0
            )
        assert result['success'] is False
        assert result['success_count'] == 0
        assert result['fail_count'] == 2

    def test_icmp_route_forwards_page_fields_and_interval(self, client):
        with patch('routes.misc_routes.icmp_sender') as sender:
            sender.send_packet.return_value = {
                'success': True, 'total_sent': 10,
                'success_count': 1, 'fail_count': 0,
            }
            response = client.post('/api/icmp/send', json={
                'target_ip': '127.0.0.1',
                'interval_ms': 777,
                'packet_data': {
                    'type': 8, 'code': 1, 'id': '0x2345', 'seq': 9,
                    'checksum': '0xabcd', 'payload': '0102',
                },
            })
        assert response.status_code == 200
        kwargs = sender.send_packet.call_args.kwargs
        assert kwargs['icmp_type'] == 8
        assert kwargs['icmp_code'] == 1
        assert kwargs['identifier'] == 0x2345
        assert kwargs['sequence'] == 9
        assert kwargs['checksum'] == 0xABCD
        assert kwargs['data'] == '0102'
        assert kwargs['interval_ms'] == 777

    def test_udp_route_forwards_interval_ms(self, client):
        with patch('routes.misc_routes.udp_sender') as sender:
            sender.send_packet.return_value = {
                'success': True, 'total_sent': 2,
                'success_count': 1, 'fail_count': 0,
            }
            response = client.post('/api/udp/send', json={
                'target_ip': '127.0.0.1', 'target_port': 9,
                'interval_ms': 888, 'packet_data': {'payload': '0102'},
            })
        assert response.status_code == 200
        assert sender.send_packet.call_args.args[-1] == 888

    def test_ping_fallback_is_not_custom_icmp_success(self):
        from backend.core.udp_icmp_sender import ICMPSender

        with patch('backend.core.udp_icmp_sender.socket.socket', side_effect=PermissionError), \
             patch('subprocess.run', return_value=Mock(returncode=0)):
            result = ICMPSender().send_packet('127.0.0.1', count=1)
        assert result['success'] is False
        assert result['custom_packet_sent'] is False
        assert result['fallback'] == 'system_ping'
        assert result['ping_reply_count'] == 1
