# -*- coding: utf-8 -*-

from scapy.sendrecv import AsyncSniffer


class Sniffer:

    def __init__(self, interface):
        self.interface = interface
        self.sniffer = AsyncSniffer(iface=interface, prn=self.__packet_handler, store=False)
        self.handlers = dict()
        self.channel = None

    def set_channel(self, channel: int):
        self.channel = channel

    def add_packet_handler(self, handler):
        self.handlers[type(handler).__name__] = handler
    
    def remove_packet_handler(self, handler):
        del self.handlers[type(handler).__name__]

    def start(self):
        self.sniffer.start()

    def stop(self):
        self.sniffer.stop()
        self.sniffer.join()

    def __packet_handler(self, pkt):
        for k, handler in self.handlers.items():
            handler(pkt)
