# -*- coding: utf-8 -*-

from scapy.utils import PcapWriter


def save(path, packets):
    with PcapWriter(path, append=False, sync=True) as f:
        f.write(packets)
