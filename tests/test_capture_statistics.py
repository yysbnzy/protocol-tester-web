# -*- coding: utf-8 -*-
"""捕获环形缓冲区与累计统计回归。"""

from backend.core import capture_manager as capture_module
from backend.core.capture_manager import PacketCaptureManager


def _fill_packets(manager, count):
    for index in range(count):
        protocol = 'UDP' if index % 250 == 0 else 'TCP'
        manager.packet_counter += 1
        packet = {
            'id': f'pkt_{manager.packet_counter}',
            'protocol': protocol,
            'is_foreign': index % 100 == 0,
        }
        manager.packet_info_buffer.append(packet)
        manager.packet_buffer.append(bytes([index % 256]))
        manager._update_capture_statistics(packet)


def test_statistics_continue_after_view_buffer_reaches_1000():
    manager = PacketCaptureManager(logger=lambda message: None)
    _fill_packets(manager, 1005)

    result = manager.get_packets()
    assert len(result['packets']) == 1000
    assert result['packets'][0]['id'] == 'pkt_6'
    assert result['packets'][-1]['id'] == 'pkt_1005'
    assert result['total_packets'] == 1005
    assert result['statistics']['total_packets'] == 1005
    assert result['statistics']['foreign_packets'] == 11
    assert result['statistics']['protocol_distribution'] == {
        'TCP': 1000,
        'UDP': 5,
    }
    assert manager.stop_capture()['total_packets'] == 1005


def test_second_capture_clears_packets_statistics_and_streams(monkeypatch):
    manager = PacketCaptureManager(logger=lambda message: None)
    _fill_packets(manager, 12)
    manager.stream_manager.streams['old-stream'] = {'packets': [1]}

    monkeypatch.setattr(capture_module, 'sniff', lambda *args, **kwargs: [])
    monkeypatch.setattr(capture_module.threading, 'Thread', lambda *args, **kwargs: type(
        'DummyThread', (), {'start': lambda self: None}
    )())

    result = manager.start_capture(interface='test0')
    assert result['success'] is True
    packets = manager.get_packets()
    assert packets['packets'] == []
    assert packets['total_packets'] == 0
    assert packets['statistics']['foreign_packets'] == 0
    assert packets['statistics']['protocol_distribution'] == {}
    assert manager.stream_manager.get_statistics()['total_streams'] == 0
    manager.is_capturing = False
