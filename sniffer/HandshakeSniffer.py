# -*- coding: utf-8 -*-

from scapy.layers.dot11 import Dot11Beacon
from scapy.layers.dot11 import Dot11
from scapy.layers.eap import EAPOL
from scapy.packet import Raw


class HandshakeSniffer:

    __NONCE = "0000000000000000000000000000000000000000000000000000000000000000"
    __MIC   = "00000000000000000000000000000000"

    def __init__(self, sniffer):
        self.sniffer = sniffer
        self._handshake_capture = []

    def __call__(self, pkt):
        if not pkt.haslayer(Dot11):
            return

        d11 = pkt.getlayer(Dot11)
        sender = d11.addr2
        receiver = d11.addr1

        if pkt.haslayer(Dot11Beacon):
            for capture in self._handshake_capture:
                if capture.pair.cell in [sender, receiver]:
                    capture.beacon = pkt

        if not pkt.haslayer(EAPOL):
            return

        for capture in self._handshake_capture:
            if capture.pair.cell in [sender, receiver]:
                self._capture_handshake(capture, pkt)
    
    def add_capture(self, capture):
        self._handshake_capture.append(capture)

    @property
    def handshake_captures(self):
        return self._handshake_capture

    def _capture_handshake(self, capture, pkt):
        if not pkt.haslayer(Raw):
            return

        d11 = pkt.getlayer(Dot11)
        sender = d11.addr2
        receiver = d11.addr1

        is_pkt_to = (d11.FCfield & 0x01) != 0
        is_pkt_from = (d11.FCfield & 0x02) != 0

        raw_pkt = pkt.getlayer(Raw)
        hex_pkt = bytes(raw_pkt).hex()

        nonce = hex_pkt[26:90]
        mic = hex_pkt[154:186]

        if is_pkt_from:
            s_r = sender == capture.pair.cell and receiver == capture.pair.client

            if s_r and nonce != self.__NONCE and mic == self.__MIC:
                capture.handshake.one = pkt
            elif s_r and nonce != self.__NONCE and mic != self.__MIC:
                capture.handshake.three = pkt
        elif is_pkt_to:
            s_r = receiver == capture.pair.cell and sender == capture.pair.client

            if s_r and nonce != self.__NONCE and mic != self.__MIC:
                capture.handshake.two = pkt
            elif s_r and nonce == self.__NONCE and mic != self.__MIC:
                capture.handshake.four = pkt

