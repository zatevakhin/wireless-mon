# -*- coding: utf-8 -*-

from enum import IntEnum
from multimethod import multimethod


class PacketFiled(IntEnum):
    SSID = 0
    CHANNEL = 3


class CellClientPair:
    def __init__(self, cell: str, client: str):
        self.client = client.lower()
        self.cell = cell.lower()

    def __eq__(self, other):
        return self.cell == other.cell and self.client == other.client

    def __repr__(self):
        return f"<{self.cell} / {self.client}>"


class FourSidedHandshake:
    def __init__(self):
        self.one = None
        self.two = None
        self.three = None
        self.four = None
    
    @property
    def packets(self):
        return [self.one, self.two, self.three, self.four]

    def __repr__(self):
        handshakes = tuple(map(lambda x: int(bool(x)), self.packets))
        return f"<{handshakes}>"


class HandshakeCapture:

    @multimethod
    def __init__(self):
        self.beacon = None
        self.handshake = FourSidedHandshake()

    @multimethod
    def __init__(self, cell: str, client: str):
        self.__init__(CellClientPair(cell, client))
    
    @multimethod
    def __init__(self, pair: CellClientPair):
        self.__init__()
        self.pair = pair

    def __eq__(self, other):
        return self.pair.cell == other.pair.cell and self.pair.client == other.pair.client

    @property
    def complete(self):
        return None not in (self.beacon, *self.handshake.packets)

    def __repr__(self):
        packets = self.handshake.packets
        packets.insert(0, self.beacon)

        packets = tuple(map(lambda x: int(bool(x)), packets))

        return f"<{self.pair.cell} -> {self.pair.client}, {packets}>"