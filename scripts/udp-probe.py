#!/usr/bin/env python3
"""Minimal manual UDP egress probe, never a WireGuard handshake test.

Run on the sending host, while capturing UDP on the receiving host.
It sends at most five harmless marked packets to ONE explicitly specified IP.
"""
from __future__ import annotations
import argparse
import ipaddress
import socket
import sys
import time

def main():
    parser=argparse.ArgumentParser(description="Cerato Network — diagnostic UDP sans scanner")
    parser.add_argument("--target",required=True,help="IPv4 de destination connue/autorisee")
    parser.add_argument("--port",required=True,type=int,help="Port UDP autorise (1..65535)")
    parser.add_argument("--count",type=int,default=3,help="1..5 paquets max")
    parser.add_argument("--interval-ms",type=int,default=350,help="100..1500 ms")
    args=parser.parse_args()
    try:
        ip=ipaddress.ip_address(args.target)
    except ValueError:
        parser.error("Adresse IPv4 invalide")
    if ip.version!=4 or ip.is_multicast or ip.is_unspecified or ip.is_loopback:
        parser.error("Utilise une adresse IPv4 cible réelle et autorisée")
    if not (1<=args.port<=65535 and 1<=args.count<=5 and 100<=args.interval_ms<=1500):
        parser.error("Port, intervalle ou nombre de paquets non autorisé")
    target=(str(ip),args.port)
    packet=b"CERATO-UDP-DIAG-v1"
    print(f"Destination : {target[0]}:{target[1]} (UDP, {args.count} paquets)")
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
        for idx in range(args.count):
            sent=sock.sendto(packet,target)
            print(f"Envoyé {idx+1}/{args.count} : {sent} octets")
            if idx+1<args.count:
                time.sleep(args.interval_ms/1000)
    print("ATTENTION : envoi local réussi != paquet reçu. Vérifier tcpdump sur la destination.")
    print("Ce paquet n'est PAS un handshake WireGuard.")

if __name__=="__main__":
    main()
