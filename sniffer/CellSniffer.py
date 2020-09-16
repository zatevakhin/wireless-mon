# -*- coding: utf-8 -*-

from scapy.layers.dot11 import Dot11Beacon
from scapy.layers.dot11 import Dot11
from scapy.layers.eap import EAPOL


class CellSniffer:

    __CLIENT_IGNORELIST = ('ff:ff:ff:ff:ff:ff')

    def __init__(self, sniffer):
        self.sniffer = sniffer
        self._access_points = list()
        self._bssid_list = set()
        self._client_list = set()
    
    @property
    def access_points(self):
        return self._access_points

    @property
    def bssid_list(self):
        return self._bssid_list

    @property
    def client_list(self):
        return self._client_list

    def __call__(self, pkt):
        if pkt.haslayer(Dot11Beacon):
            beacon = pkt.getlayer(Dot11Beacon)
            bssid = pkt.getlayer(Dot11).addr2

            if bssid not in self._bssid_list:
                self._bssid_list.add(bssid)
                # ap_stats = beacon.network_stats()
                # del ap_stats["rates"]

                # ap_stats.update()
                # ap_stats.update({})

                self._access_points.append({"bssid": bssid, "clients": []})
        
        if pkt.haslayer(Dot11) and pkt.getlayer(Dot11).type == 2 and not pkt.haslayer(EAPOL):
            d11 = pkt.getlayer(Dot11)
            s = d11.addr2
            r = d11.addr1

            tg_bssid = None
            ap_bssid = None

            if s in self._bssid_list:
                tg_bssid, ap_bssid = r, s
            elif r in self._bssid_list:
                tg_bssid, ap_bssid = s, r

            if tg_bssid and tg_bssid not in self._client_list:
                for ap in self._access_points:
                    if ap["bssid"] == ap_bssid and tg_bssid not in self.__CLIENT_IGNORELIST:
                        ap["clients"].append(tg_bssid)
                        self._client_list.add(tg_bssid)
