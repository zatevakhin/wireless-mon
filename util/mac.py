# -*- coding: utf-8 -*-

import re


MULTICAST_MAC = [
    "01:00:0C:CC:CC:CD",
    "01:00:0C:CC:CC:CC",
    "01:1B:19:00:00:00",
    "00:00:00:00:00:00",
    "01:80:C2:00:00",
    "01:00:5E",
    "01:0C:CD",
    "33:33",
    "01:00:5e"
]


def is_mac(mac: str) -> bool:
    return bool(re.match(r"^(?:[a-f0-9]{2}:){5}[a-f0-9]{2}$", mac, re.I))


def is_multicast(mac: str) -> bool:
    return is_mac(mac) and bool(list(filter(lambda x: mac.startswith(x.lower()), MULTICAST_MAC)))
