#!/usr/bin/env python3
"""
ARP-spoofing detector.
Слушает ARP-ответы на интерфейсе и сравнивает MAC с эталонным.
Если MAC не совпадает — выводит алерт.
"""

from scapy.all import sniff, ARP, get_if_hwaddr
import sys

IFACE = "enp0s8"

KNOWN_HOSTS = {
    "172.16.1.1":   "08:00:27:8c:eb:6c",
    "172.16.1.101": "08:00:27:64:91:c7",
    "172.16.1.50":  "08:00:27:b2:ea:78",
}

def handle_packet(pkt):
    if not pkt.haslayer(ARP):
        return
    if pkt[ARP].op != 2:
        return

    ip = pkt[ARP].psrc
    mac = pkt[ARP].hwsrc

    if ip in KNOWN_HOSTS and KNOWN_HOSTS[ip] != mac:
        print(f"[!] ARP-SPOOF DETECTED: {ip} is-at {mac} (ожидался {KNOWN_HOSTS[ip]})")

def main():
    iface = sys.argv[1] if len(sys.argv) > 1 else IFACE
    print(f"[*] Слушаю ARP на {iface}...")
    print(f"[*] Эталонные хосты: {KNOWN_HOSTS}")
    print(f"[*] Ctrl+C для остановки\n")
    try:
        sniff(iface=iface, filter="arp", prn=handle_packet, store=False)
    except KeyboardInterrupt:
        print("\n[*] Остановлено")
    except PermissionError:
        print("[!] Нужны права root: sudo python3 arp_detect.py")
        sys.exit(1)

if __name__ == "__main__":
    main()
