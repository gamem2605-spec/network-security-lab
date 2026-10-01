# Network Security Lab

Лабораторный полигон для изучения сетевых атак и защиты.

## Компоненты
- **ALT Server** (172.16.1.1) — цель
- **ALT Workstation** (172.16.1.101) — вторая жертва
- **Kali Linux** (172.16.1.50) — атакующий

## Что реализовано

### Атаки
- ARP-spoofing + MITM
- DNS-spoofing (свой скрипт на Python/scapy)

### Детект
- `arp_detect.py` — детектор ARP-spoofing на Python

### Защита
- Статические ARP-записи (`PERMANENT`)
- Firewall (`iptables`) — ограничение портов
- NFS hardening — ограничение по IP, `root_squash`

## Скрипты
- `arp_detect.py` — детект ARP-spoofing
- `dns_spoof.py` — DNS-spoofing

## Стек
Linux (ALT), Kali, Python, scapy, nmap, tcpdump, iptables
